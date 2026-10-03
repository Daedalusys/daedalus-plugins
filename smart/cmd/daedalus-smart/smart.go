// smart.go 是 daedalus.smart 的实现:smartctl 读取盘 SMART 健康/属性/自检能力。
//
// 与 avc/gpu 的关键差异:smartctl 的**退出码是位掩码**(health 位/错误位),
// "非零≠错误"。把位掩码当致命错误会把"健康检查通过但有警告位"误判为失败。
// 因此 handleExecError 把位掩码翻译成语义化 note,只有真 stderr 才判 fatal。
//
// runner 设计与 avc 一致:可注入 execRunner 走单测替身;真 fork 仅在
// TestExecHelper_Real* 与 Test*_RealStderr* 系列用假脚本验证 stderr/退出码管道。
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// smartTimeout 是单次 smartctl 调用超时。SMART 读取不慢,但磁盘在低功耗
// 状态下唤醒可能超 1s,给足 30s 兜底。
const smartTimeout = 30 * time.Second

// defaultSmartctlPath 是找不到 smartctl 时的兜底路径。
const defaultSmartctlPath = "/usr/sbin/smartctl"

// resolveSmartctl 用 exec.LookPath 定位 smartctl,失败则回退到默认路径。
// 返回非空字符串(本批语义下 smartctl 几乎总是装着,所以不返回空)。
func resolveSmartctl() string {
	if p, err := exec.LookPath("smartctl"); err == nil && p != "" {
		return p
	}
	return defaultSmartctlPath
}

// --- 类型定义(对应 manifest tool 的 JSON schema)---

// Disk 是 `smart_list` 的条目:一条 smartctl --scan 输出。
type Disk struct {
	Name string `json:"name"`           // 设备路径,如 /dev/sda
	Type string `json:"type,omitempty"` // smartctl -d 类型,如 sat/scsi/nvme
	Info string `json:"info,omitempty"` // `# ` 后的备注段
}

// ScanResult 是 `smart_list` 的返回。
type ScanResult struct {
	Disks []Disk `json:"disks"`
	Note  string `json:"note,omitempty"`
}

// HealthResult 是 `smart_health` 的返回。Passed 是综合判定(文本 + bit 3),
// ExitBitmask 原样回传 smartctl 退出码以便调用方自行核对位语义。
type HealthResult struct {
	Disk        string `json:"disk"`
	Passed      bool   `json:"passed"`
	ExitBitmask int    `json:"exit_bitmask"`
	Note        string `json:"note,omitempty"`
}

// AttributeSet 是 `smart_attributes` 的返回。Attrs 键是 canonical 属性名,
// 值是 RAW_VALUE(原始值)。
type AttributeSet struct {
	Disk   string         `json:"disk"`
	Vendor string         `json:"vendor,omitempty"`
	Attrs  map[string]int `json:"attrs"`
	Note   string         `json:"note,omitempty"`
}

// SmartTestResult 是 `smart_test` 的返回。L1 本批 deferred:Started 恒 false,
// 不真触发磁盘自检 I/O。
type SmartTestResult struct {
	Disk    string `json:"disk"`
	Kind    string `json:"kind"`
	Started bool   `json:"started"`
	Note    string `json:"note"`
}

// SmartDiskArgs 是 `smart_health` / `smart_attributes` 的入参。
type SmartDiskArgs struct {
	Disk string `json:"disk"`
}

// SmartTestArgs 是 `smart_test` 的入参。kind 可选,默认 short。
type SmartTestArgs struct {
	Disk string `json:"disk"`
	Kind string `json:"kind,omitempty"`
}

// validateSmartTestKind 校验 kind 只在 short|long 白名单内。严格区分大小写,
// 与 JSON schema Enum 语义对齐(避免 schema 放行 / Go 收紧的语义割裂)。
func validateSmartTestKind(kind string) (string, error) {
	switch kind {
	case "":
		return "short", nil
	case "short", "long":
		return kind, nil
	}
	return "", fmt.Errorf("kind=%q 不在白名单(short|long)", kind)
}

// --- 磁盘路径校验 ---

// DiskDevicePatternString 是磁盘路径白名单正则的单一事实源:main.go 的 JSON
// schema Pattern 与本文件的运行期校验共用同一字面量,避免两处副本静默漂移。
const DiskDevicePatternString = `^/dev/(sd[a-z]+|vd[a-z]+|hd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)(p?[0-9]+)?$`

// diskDevicePattern 限定可接受的块设备命名。白名单外一律拒(md/loop/zram 等
// 不在本批范围),避免把任意路径喂给 smartctl。
var diskDevicePattern = regexp.MustCompile(DiskDevicePatternString)

// validateDiskPath 校验 disk 参数。即便 argv 直发(无 shell),"-注入"与
// 空白拼接仍可能让 smartctl 把其后的 token 当选项;故显式拒绝 `..`、
// 空白、前导 `-`、空字节、shell 元字符,再叠加命名白名单正则。
func validateDiskPath(disk string) error {
	if disk == "" {
		return errors.New("disk 不能为空")
	}
	if strings.ContainsRune(disk, 0) {
		return errors.New("disk 含空字节")
	}
	if strings.ContainsAny(disk, " \t\n\r\f\v") {
		return errors.New("disk 含空白字符")
	}
	if strings.Contains(disk, "..") {
		return errors.New("disk 含目录遍历序列 ..")
	}
	if strings.HasPrefix(disk, "-") {
		return errors.New("disk 不能以 - 开头(选项注入)")
	}
	if strings.ContainsAny(disk, ";|&$`*()[]{}<>\"'\\~!#") {
		return errors.New("disk 含 shell 元字符")
	}
	if !filepath.IsAbs(disk) {
		return errors.New("disk 必须是绝对路径")
	}
	if !diskDevicePattern.MatchString(disk) {
		return fmt.Errorf("disk=%q 不在可接受的块设备白名单(sd/vd/hd/xvd/nvme/mmcblk)", disk)
	}
	return nil
}

// --- 可移植 runner(core)---
// 与 avc.go 同名同语义;不跨插件 import(三插件共享一份)。

// execError 包装一次失败的外部进程调用:退出码 + 真实 stderr。
// Stderr 为空 + Code 非零 是"位掩码非致命错"的特征(见 handleExecError)。
type execError struct {
	Code   int
	Stderr string
	Cause  error
}

func (e *execError) Error() string {
	if e.Stderr != "" {
		return fmt.Sprintf("%s: %s", e.Cause.Error(), strings.TrimSpace(e.Stderr))
	}
	return e.Cause.Error()
}

func (e *execError) Unwrap() error { return e.Cause }

// isMissingBinary 判定 err 是否源于外部可执行文件缺失/不可执行。
// errors.Is 自动解包 *fs.PathError,无需手动 errors.As;fs.ErrPermission
// 保留一次(不可执行亦降级 note,不 fatal)。
func isMissingBinary(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) ||
		errors.Is(err, fs.ErrInvalid) || errors.Is(err, exec.ErrNotFound)
}

// execHelper 以 argv 直发执行外部进程:逐行回传 stdout,失败包装为 execError
// (携带退出码 + 真实 stderr)。**cmd.Stderr = &stderr 必须在 cmd.Start() 之前**,
// 否则子进程 stderr 会被丢到宿主 stderr、错误链丢失真实原因(见 Task 3 教训)。
//
// onLine 返回 false 即中止继续读取(用于大输出提前退出)。
func execHelper(ctx context.Context, bin string, stdin io.Reader, onLine func([]byte) bool, args ...string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = stdin

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("接管 %s stdout 失败: %w", bin, err)
	}

	// 关键:stderr 必须在 Start() 之前接管 —— 见 avc_test/Task 3 回归测试。
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		if isMissingBinary(err) {
			return fmt.Errorf("无法启动 %s: %w", bin, err)
		}
		return fmt.Errorf("启动 %s 失败: %w", bin, err)
	}

	// 逐行读 stdout;Scanner 默认 64KB 上限,SMART 输出远小于该值。
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if !onLine(sc.Bytes()) {
			break
		}
	}
	scanErr := sc.Err()

	waitErr := cmd.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if scanErr != nil {
		return fmt.Errorf("读取 %s stdout 失败: %w", bin, scanErr)
	}
	if waitErr != nil {
		code := -1
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			code = ee.ExitCode()
		}
		return &execError{
			Code:   code,
			Stderr: stderrBuf.String(),
			Cause:  fmt.Errorf("%s 退出码 %d", filepath.Base(bin), code),
		}
	}
	return nil
}

// --- smartctl 退出码位语义 ---
// 来源:man smartctl EXIT STATUS(逐位语义见 smart_test.go 测试)。
// rc=0 → ""; 非零 → 逐位列出 "; " 连接。

// smartctlBitNames 是 bit 0..7 的语义文案。
var smartctlBitNames = [8]string{
	"bit 0 (Command line did not parse)",
	"bit 1 (Device open failed / no IDENTIFY / low-power mode)",
	"bit 2 (SMART or ATA command failed / checksum error)",
	`bit 3 (SMART status check returned "DISK FAILING")`,
	"bit 4 (Prefail attributes <= threshold)",
	`bit 5 (SMART status "DISK OK" but attributes were <= threshold in the past)`,
	"bit 6 (Device error log contains records of errors)",
	"bit 7 (Device self-test log contains records of errors)",
}

// translateSmartctlBitmask 把 smartctl 退出码位掩码翻译成语义 note。
// rc<=0 或无位设置 → ""。
func translateSmartctlBitmask(rc int) string {
	if rc <= 0 {
		return ""
	}
	var parts []string
	for i := 0; i < len(smartctlBitNames); i++ {
		if rc&(1<<i) != 0 {
			parts = append(parts, smartctlBitNames[i])
		}
	}
	return strings.Join(parts, "; ")
}

// handleExecError 把 execHelper 的错误翻译成 (note, bitmask, fatal)。
//
// 裁决规则(核心):
//   - err == nil → ("", 0, false)
//   - binary 缺失 → note 说明,不 fatal(插件健康,只是依赖未装)
//   - execError 且 Stderr 非空 → fatal:真 stderr 是结构性失败,必须上抛
//   - execError 且 Stderr 为空 → 位掩码健康位,翻译成 note,不 fatal
//   - 其它(ctx.Err / 管道失败)→ fatal
//
// "Stderr 为空" 判定的实证依据:smartctl 7.2 在权限不足/设备不存在时把错误
// 写 **stdout**,stderr 空、rc 置位 1;而 `/sys` 读失败走真 stderr + rc=2。
func handleExecError(err error) (note string, bitmask int, fatal bool) {
	if err == nil {
		return "", 0, false
	}
	if isMissingBinary(err) {
		return "smartctl 不可用(未安装 smartmontools)", 0, false
	}
	var ee *execError
	if !errors.As(err, &ee) {
		return "", 0, true
	}
	if ee.Stderr != "" {
		return "", 0, true
	}
	return translateSmartctlBitmask(ee.Code), ee.Code, false
}

// --- 解析基元 ---

// parseScanText 解析 `smartctl --scan` 输出,提取 `Name -d Type # Info`。
// 兼容旧格式(无 `-d <type>`)与注释/空行。
func parseScanText(lines [][]byte) []Disk {
	disks := []Disk{}
	for _, line := range lines {
		raw := strings.TrimSpace(string(line))
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		left, info, _ := strings.Cut(raw, "#")
		info = strings.TrimSpace(info)

		fields := strings.Fields(strings.TrimSpace(left))
		if len(fields) == 0 {
			continue
		}
		d := Disk{Name: fields[0], Info: info}
		for i := 1; i < len(fields)-1; i++ {
			if fields[i] == "-d" {
				d.Type = fields[i+1]
				break
			}
		}
		disks = append(disks, d)
	}
	return disks
}

// parseHealthPassed 解析 `-H` 输出,识别两类健康行:
//
//	"SMART overall-health self-assessment test result: PASSED|FAILED!"
//	"SMART Health Status: OK|..."
//
// 多行冲突时 FAILED 优先(保守:有失败信号即不宣称健康)。无健康行(如
// 设备打开失败)→ false。
func parseHealthPassed(lines [][]byte) bool {
	passed := false
	found := false
	for _, line := range lines {
		t := strings.TrimSpace(string(line))
		if !strings.Contains(t, "SMART overall-health self-assessment test result") &&
			!strings.Contains(t, "SMART Health Status") {
			continue
		}
		idx := strings.LastIndex(t, ":")
		if idx < 0 {
			continue
		}
		v := strings.ToUpper(strings.TrimSpace(t[idx+1:]))
		switch {
		case strings.HasPrefix(v, "FAILED"):
			return false
		case v == "OK", v == "PASSED":
			passed = true
			found = true
		}
	}
	if !found {
		return false
	}
	return passed
}

// attributeWhitelist 是 `smart_attributes` 关心的 canonical 属性名白名单
// (ATA 表字段名 + NVMe 映射目标)。
var attributeWhitelist = map[string]bool{
	"Temperature_Celsius":             true,
	"Power_On_Hours":                  true,
	"Reallocated_Sector_Ct":           true,
	"Current_Pending_Sector":          true,
	"Offline_Uncorrectable":           true,
	"Available_Spare":                 true,
	"Percentage_Used":                 true,
	"Media_And_Data_Integrity_Errors": true,
	"Error_Information_Log_Entries":   true,
	"Power_Cycles":                    true,
	"Unsafe_Shutdowns":                true,
}

// nvmeAttrAliases 把 NVMe `Key:` 标签映射到 canonical 名。
var nvmeAttrAliases = map[string]string{
	"temperature":                     "Temperature_Celsius",
	"power on hours":                  "Power_On_Hours",
	"available spare":                 "Available_Spare",
	"percentage used":                 "Percentage_Used",
	"media and data integrity errors": "Media_And_Data_Integrity_Errors",
	"error information log entries":   "Error_Information_Log_Entries",
	"power cycles":                    "Power_Cycles",
	"unsafe shutdowns":                "Unsafe_Shutdowns",
}

// vendorFieldNames 是 vendor 抓取的优先级顺序(逐个尝试,取首个非空)。
var vendorFieldNames = []string{"Vendor", "Model Family", "Device Model", "Model Number"}

// parseAttributes 解析 `-A` 输出:ATA 走属性表(字段名 + RAW_VALUE 末字段),
// NVMe 走 `Key: Value`。非数值 RAW_VALUE 跳过(不塞 0)。
func parseAttributes(lines [][]byte) AttributeSet {
	attrs := make(map[string]int)
	vendor := ""

	for _, line := range lines {
		raw := strings.TrimSpace(string(line))
		if raw == "" {
			continue
		}

		// vendor 抓取:`Vendor: ...` / `Model Family: ...` / `Device Model: ...`
		if vendor == "" {
			if v := extractVendorLine(raw); v != "" {
				vendor = v
			}
		}

		// ATA 表头标记:后面才是属性行。
		// 属性行特征:首字段是整数 ID,次字段是属性名(下划线/数字)。
		if k, v, ok := parseATARow(raw); ok {
			if attributeWhitelist[k] {
				attrs[k] = v
			}
			continue
		}

		// NVMe `Key: Value` 形态。
		if k, v, ok := parseNVMeRow(raw); ok {
			if attributeWhitelist[k] {
				attrs[k] = v
			}
		}
	}
	return AttributeSet{Vendor: vendor, Attrs: attrs}
}

// extractVendorLine 从一行里提取 vendor 字段值。
func extractVendorLine(raw string) string {
	idx := strings.Index(raw, ":")
	if idx < 0 {
		return ""
	}
	key := strings.TrimSpace(raw[:idx])
	for _, want := range vendorFieldNames {
		if strings.EqualFold(key, want) {
			return strings.TrimSpace(raw[idx+1:])
		}
	}
	return ""
}

// parseATARow 解析一行 ATA 属性行:
//
//	ID# ATTRIBUTE_NAME FLAG VALUE WORST THRESH TYPE UPDATED WHEN_FAILED RAW_VALUE
//
// 至少 10 字段,首字段是整数 ID,末字段前一个是 WHEN_FAILED。
// RAW_VALUE 可能带尾注(如 "35 (Min/Max 20/45)"),取首 token。
func parseATARow(raw string) (string, int, bool) {
	fields := strings.Fields(raw)
	if len(fields) < 10 {
		return "", 0, false
	}
	if _, err := strconv.Atoi(fields[0]); err != nil {
		return "", 0, false
	}
	name := fields[1]
	// 过滤表头行本身(ID# 非整数已被 Atoi 拦掉)。
	rawVal := fields[9]
	// RAW_VALUE 带尾注:"35 (Min/Max 20/45)" → 取 "35";但 "(" 起的尾注会被
	// Fields 拆成独立 token,故 fields[9] 已是首 token。
	n, err := strconv.ParseInt(rawVal, 0, 64)
	if err != nil {
		return "", 0, false
	}
	return name, int(n), true
}

// parseNVMeRow 解析一行 `Key: Value` 形态,把 Key 映射到 canonical 名。
// Value 可能带千分位逗号("8,760")或单位("35 Celsius"、"100%")。
func parseNVMeRow(raw string) (string, int, bool) {
	idx := strings.Index(raw, ":")
	if idx < 0 {
		return "", 0, false
	}
	key := strings.ToLower(strings.TrimSpace(raw[:idx]))
	canonical, ok := nvmeAttrAliases[key]
	if !ok {
		return "", 0, false
	}
	val := strings.TrimSpace(raw[idx+1:])
	// 去单位后缀(非数字部分)。
	numeric := takeNumericPrefix(val)
	numeric = strings.ReplaceAll(numeric, ",", "")
	if numeric == "" {
		return "", 0, false
	}
	n, err := strconv.ParseInt(numeric, 0, 64)
	if err != nil {
		return "", 0, false
	}
	return canonical, int(n), true
}

// takeNumericPrefix 取字符串开头的数字(含可选千分位逗号/小数点)部分。
func takeNumericPrefix(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for i, r := range s {
		if (r >= '0' && r <= '9') || r == ',' || r == '.' {
			b.WriteRune(r)
			continue
		}
		if i == 0 && (r == '-' || r == '+') {
			b.WriteRune(r)
			continue
		}
		break
	}
	return b.String()
}

// --- 服务层 ---

// execRunner 是可注入的外部进程执行器;单测用 fakeRunner 替换。
type execRunner func(ctx context.Context, bin string, stdin io.Reader, onLine func([]byte) bool, args ...string) error

// service 是 smart 工具集的实现。timeout 为单次 smartctl 调用超时。
// binary 是 smartctl 路径(单测可注入假脚本)。
type service struct {
	run     execRunner
	timeout time.Duration
	binary  string
}

// newService 装配默认 service(真 execHelper + smartTimeout + 解析 smartctl 路径)。
func newService() *service {
	return &service{run: execHelper, timeout: smartTimeout, binary: resolveSmartctl()}
}

// runSmartctl 执行 smartctl 并收集逐行 stdout。
func (s *service) runSmartctl(ctx context.Context, args ...string) ([][]byte, error) {
	execCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var lines [][]byte
	err := s.run(execCtx, s.binary, nil, func(b []byte) bool {
		lines = append(lines, append([]byte(nil), b...))
		return true
	}, args...)
	return lines, err
}

// List 跑 `smartctl --scan`,返回所有磁盘。
func (s *service) List(ctx context.Context) (ScanResult, error) {
	lines, err := s.runSmartctl(ctx, "--scan")
	note, _, fatal := handleExecError(err)
	if fatal {
		return ScanResult{}, fmt.Errorf("smart_list 失败: %w", err)
	}
	disks := parseScanText(lines)
	if disks == nil {
		disks = []Disk{}
	}
	return ScanResult{Disks: disks, Note: note}, nil
}

// Health 跑 `smartctl -H <disk>`,综合文本判定 + bit 3 得出 Passed。
func (s *service) Health(ctx context.Context, args SmartDiskArgs) (HealthResult, error) {
	if err := validateDiskPath(args.Disk); err != nil {
		return HealthResult{}, err
	}
	lines, err := s.runSmartctl(ctx, "-H", args.Disk)
	note, bitmask, fatal := handleExecError(err)
	if fatal {
		return HealthResult{}, fmt.Errorf("smart_health 失败: %w", err)
	}
	passed := parseHealthPassed(lines)
	// bit 3 = "DISK FAILING" 是权威健康信号,即便文本 PASSED 也钳制为 false。
	if bitmask&(1<<3) != 0 {
		passed = false
	}
	return HealthResult{
		Disk:        args.Disk,
		Passed:      passed,
		ExitBitmask: bitmask,
		Note:        note,
	}, nil
}

// Attributes 跑 `smartctl -A <disk>`,返回白名单内的关键属性。
func (s *service) Attributes(ctx context.Context, args SmartDiskArgs) (AttributeSet, error) {
	if err := validateDiskPath(args.Disk); err != nil {
		return AttributeSet{}, err
	}
	lines, err := s.runSmartctl(ctx, "-A", args.Disk)
	note, _, fatal := handleExecError(err)
	if fatal {
		return AttributeSet{}, fmt.Errorf("smart_attributes 失败: %w", err)
	}
	got := parseAttributes(lines)
	got.Disk = args.Disk
	got.Note = note
	return got, nil
}

// Test 是 `smart_test` 的实现:L1 本批 deferred —— 不 fork、不触发磁盘自检 I/O。
// 需 y/n 确认令牌后才允许真启动;本批未走 daedalus-tx/confirm_token,故一律
// 返回 Started=false + 解释 note,并透传回显 disk/kind 供 LLM 引用。
func (s *service) Test(ctx context.Context, args SmartTestArgs) (SmartTestResult, error) {
	if err := validateDiskPath(args.Disk); err != nil {
		return SmartTestResult{}, err
	}
	kind, err := validateSmartTestKind(args.Kind)
	if err != nil {
		return SmartTestResult{}, err
	}
	_ = ctx
	return SmartTestResult{
		Disk: args.Disk,
		Kind: kind,
		// Started 恒 false:L1 本批 deferred,未触发任何磁盘 I/O。
		Started: false,
		Note:    "L1 自检需 y/n 确认令牌,本批未启用;未触发任何磁盘 I/O",
	}, nil
}
