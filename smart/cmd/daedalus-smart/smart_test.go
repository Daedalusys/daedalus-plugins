// smart 解析基元与外部 CLI 编排的单测:夹具驱动 + 注入替身零触碰宿主磁盘。
// 核心在钉住"smartctl 退出码是位掩码(非错误)"的 handleExecError 行为,
// 与 L1 deferred 决策。
package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fixtureDir 是 testdata/ 的相对路径,测试在包目录内执行。
const fixtureDir = "testdata"

// loadFixture 读 testdata 下文本夹具。
func loadFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("读夹具 %s 失败: %v", name, err)
	}
	return string(b)
}

// splitFixture 把夹具按行拆分,模拟 stdout 逐行回传。
func splitFixture(t *testing.T, name string) [][]byte {
	t.Helper()
	content := loadFixture(t, name)
	var out [][]byte
	for _, line := range strings.Split(content, "\n") {
		out = append(out, []byte(line))
	}
	return out
}

// fakeRunner 是 execRunner 夹具:按 results 顺序分配每次 smartctl 调用的
// stdout/err;记录调用次数、argv 与 stdin,便于断言"不 fork"与 command line。
type fakeRunner struct {
	calls   int
	results []fakeResult
	lastBin string
	lastArg []string
	stdin   []byte
}

// fakeResult 是单次调用的脚本:lines 逐行喂 onLine;err 在喂完后返回
// (execError / fs.PathError);希望 onLine 返回 false 即中止时用 abortOnLine。
type fakeResult struct {
	lines       [][]byte
	err         error
	abortOnLine bool
}

func (f *fakeRunner) run(_ context.Context, bin string, stdin io.Reader, onLine func([]byte) bool, args ...string) error {
	f.lastBin = bin
	f.lastArg = append([]string(nil), args...)
	if stdin != nil {
		b, _ := io.ReadAll(stdin)
		f.stdin = append([]byte(nil), b...)
	}
	idx := f.calls
	f.calls++
	if idx >= len(f.results) {
		return nil
	}
	r := f.results[idx]
	for _, line := range r.lines {
		if !onLine(line) && r.abortOnLine {
			return nil
		}
	}
	return r.err
}

// newFakeService 装配挂 fakeRunner 的 service;binary 用哨兵值方便断言。
func newFakeService(results ...fakeResult) (*service, *fakeRunner) {
	fr := &fakeRunner{results: results}
	return &service{run: fr.run, timeout: smartTimeout, binary: "smartctl-stub"}, fr
}

// --- 磁盘路径校验 ---

// TestValidateDiskPath 合法/非法磁盘路径形态;重点覆盖注入向量(`..`、空白、
// `-注入`、`--scan` 拼接、shell 元字符、空字节)。
func TestValidateDiskPath(t *testing.T) {
	valid := []string{
		"/dev/sda", "/dev/sdb", "/dev/sdz", "/dev/sda1", "/dev/sdz12",
		"/dev/vda", "/dev/vdc3", "/dev/hda", "/dev/xvda",
		"/dev/nvme0n1", "/dev/nvme1n2", "/dev/nvme0n1p1", "/dev/nvme12n3p45",
		"/dev/mmcblk0", "/dev/mmcblk0p1",
	}
	for _, d := range valid {
		if err := validateDiskPath(d); err != nil {
			t.Errorf("validateDiskPath(%q) 应通过, got %v", d, err)
		}
	}

	invalid := []string{
		"",
		"sda",                     // 非绝对
		"/dev/sda --scan",         // 注入拼接
		"/dev/sda\n",              // 行尾注入
		"/dev/sda\t-d\tsat",       // 空白注入
		"/dev/../etc/passwd",      // 目录遍历
		"/dev/../../etc/shadow",   // 深层遍历
		"/dev/sd a",               // 内嵌空格
		"-H",                      // 选项注入
		"-d sat",                  // 选项注入
		"/dev/sda; rm -rf /",      // shell 元字符(即便 argv 直发也拒)
		"/dev/sda|cat",            // 管道
		"/dev/sda`id`",            // 反引号
		"/dev/sda$(id)",           // 命令替换
		"/dev/sda&",               // 后台
		"/dev/sda*",               // 通配
		"/dev/",                   // 仅前缀
		"/dev/sd",                 // 太短
		"/etc/passwd",             // 非 /dev 域
		"/dev/md0",                // 软 RAID 不在白名单
		"/dev/loop0",              // loop 不在白名单
		"/dev/sda\x00",            // 空字节
		"/dev/sda ",               // 尾部空白
		" /dev/sda",               // 前导空白
		"/dev/sda\x00/etc/passwd", // 空字节截断
		"/dev/nvme0",              // NVMe 缺 n 段
		"/dev/nvme0n1x",           // NVMe 尾随脏字符
		"/dev/sda/../sdb",         // 中间遍历
	}
	for _, d := range invalid {
		if err := validateDiskPath(d); err == nil {
			t.Errorf("validateDiskPath(%q) 应拒绝, got nil", d)
		}
	}
}

// TestService_DiskInjectionRejected 服务层入口必须在校验失败时立即返回错误,
// 绝不 fork smartctl(fakeRunner.calls 必须为 0)。
func TestService_DiskInjectionRejected(t *testing.T) {
	for _, name := range []string{"Health", "Attributes"} {
		svc, fr := newFakeService()
		args := SmartDiskArgs{Disk: "/dev/sda --scan"}
		var err error
		switch name {
		case "Health":
			_, err = svc.Health(context.Background(), args)
		case "Attributes":
			_, err = svc.Attributes(context.Background(), args)
		}
		if err == nil {
			t.Errorf("%s 注入 disk 应拒绝, got nil", name)
		}
		if fr.calls != 0 {
			t.Errorf("%s 注入 disk 不应 fork, got calls=%d", name, fr.calls)
		}
	}
}

// --- 扫描解析 ---

// TestParseScanText 三条 `--scan` 夹具必须解析为 3 个 Disk{ Name, Type, Info }。
func TestParseScanText(t *testing.T) {
	lines := splitFixture(t, "scan.txt")
	got := parseScanText(lines)
	want := []Disk{
		{Name: "/dev/sda", Type: "sat", Info: "/dev/sda [SAT], ATA device"},
		{Name: "/dev/sdb", Type: "scsi", Info: "/dev/sdb, SCSI device"},
		{Name: "/dev/nvme0n1", Type: "nvme", Info: "/dev/nvme0n1, NVMe device"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseScanText = %+v\nwant %+v", got, want)
	}
}

// TestParseScanText_OldFormatNoDashD 兼容老格式(无 `-d <type>`):type 退化为空。
func TestParseScanText_OldFormatNoDashD(t *testing.T) {
	lines := [][]byte{[]byte("/dev/sda # /dev/sda, ATA device")}
	got := parseScanText(lines)
	want := []Disk{{Name: "/dev/sda", Type: "", Info: "/dev/sda, ATA device"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseScanText(旧格式) = %+v\nwant %+v", got, want)
	}
}

// TestParseScanText_SkipsCommentAndBlank 注释行 / 空行必须跳过(不产空 Disk)。
func TestParseScanText_SkipsCommentAndBlank(t *testing.T) {
	lines := [][]byte{
		[]byte(""),
		[]byte("# /dev/sda -d sat # 备注"),
		[]byte("/dev/sda -d sat # /dev/sda [SAT], ATA device"),
		[]byte("   "),
	}
	got := parseScanText(lines)
	if len(got) != 1 {
		t.Fatalf("解析得 %d 条, want 1: %+v", len(got), got)
	}
	if got[0].Name != "/dev/sda" {
		t.Errorf("Name = %q, want /dev/sda", got[0].Name)
	}
}

// --- 健康解析 ---

// TestParseHealthPassed_* 覆盖 ATA PASSED / FAILED / SCSI `SMART Health Status: OK`。
func TestParseHealthPassed_Passed(t *testing.T) {
	got := parseHealthPassed(splitFixture(t, "health-passed.txt"))
	if got != true {
		t.Errorf("health-passed 应 true, got %v", got)
	}
}

func TestParseHealthPassed_Failed(t *testing.T) {
	got := parseHealthPassed(splitFixture(t, "health-failed.txt"))
	if got != false {
		t.Errorf("health-failed 应 false, got %v", got)
	}
}

func TestParseHealthPassed_ScsiOK(t *testing.T) {
	got := parseHealthPassed(splitFixture(t, "health-scsi-ok.txt"))
	if got != true {
		t.Errorf("health-scsi-ok 应 true, got %v", got)
	}
}

// TestParseHealthPassed_NoStatusLine 无健康行(设备打开失败)保守返 false。
func TestParseHealthPassed_NoStatusLine(t *testing.T) {
	lines := [][]byte{
		[]byte("smartctl 7.2 ..."),
		[]byte("Smartctl open device: /dev/sda failed: Permission denied"),
	}
	if parseHealthPassed(lines) != false {
		t.Errorf("无健康行应保守 false")
	}
}

// TestParseHealthPassed_FailedWinsOverPassed 同时含 PASSED 与 FAILED 时以
// FAILED 为准(保守:只要有失败信号即不宣称健康)。
func TestParseHealthPassed_FailedWinsOverPassed(t *testing.T) {
	lines := [][]byte{
		[]byte("SMART overall-health self-assessment test result: PASSED"),
		[]byte("Previous self-test FAILED"),
	}
	// 注:"Previous self-test FAILED" 不是 health 状态行,不会被认成 FAILED;
	// 但若真出现两个 health 行(如分屏输出),FAILED 优先。
	lines2 := [][]byte{
		[]byte("SMART overall-health self-assessment test result: PASSED"),
		[]byte("SMART overall-health self-assessment test result: FAILED!"),
	}
	if parseHealthPassed(lines2) != false {
		t.Errorf("FAILED 应优先于 PASSED")
	}
	if parseHealthPassed(lines) != true {
		t.Errorf("非健康状态行不应影响 PASSED 判定")
	}
}

// --- 属性解析 ---

// TestParseAttributes_ATA ATA 5 关键属性必须齐全,且 RAW_VALUE 取末字段。
func TestParseAttributes_ATA(t *testing.T) {
	got := parseAttributes(splitFixture(t, "attributes-ata.txt"))
	if got.Vendor != "Samsung based SSDs" {
		t.Errorf("Vendor = %q, want %q", got.Vendor, "Samsung based SSDs")
	}
	want := map[string]int{
		"Temperature_Celsius":    35,
		"Power_On_Hours":         8760,
		"Reallocated_Sector_Ct":  0,
		"Current_Pending_Sector": 0,
		"Offline_Uncorrectable":  0,
	}
	for k, w := range want {
		if got.Attrs[k] != w {
			t.Errorf("Attrs[%s] = %d, want %d", k, got.Attrs[k], w)
		}
	}
}

// TestParseAttributes_NVMe NVMe `Key: Value` 形态必须映射到 canonical 名。
func TestParseAttributes_NVMe(t *testing.T) {
	got := parseAttributes(splitFixture(t, "attributes-nvme.txt"))
	if got.Vendor != "Samsung SSD 970 EVO Plus 1TB" {
		t.Errorf("Vendor = %q, want Model Number 值", got.Vendor)
	}
	if got.Attrs["Temperature_Celsius"] != 35 {
		t.Errorf("Temperature_Celsius = %d, want 35", got.Attrs["Temperature_Celsius"])
	}
	if got.Attrs["Power_On_Hours"] != 8760 {
		t.Errorf("Power_On_Hours = %d, want 8760", got.Attrs["Power_On_Hours"])
	}
	if got.Attrs["Available_Spare"] != 100 {
		t.Errorf("Available_Spare = %d, want 100", got.Attrs["Available_Spare"])
	}
	if got.Attrs["Percentage_Used"] != 0 {
		t.Errorf("Percentage_Used = %d, want 0", got.Attrs["Percentage_Used"])
	}
	if got.Attrs["Media_And_Data_Integrity_Errors"] != 0 {
		t.Errorf("Media_And_Data_Integrity_Errors = %d, want 0", got.Attrs["Media_And_Data_Integrity_Errors"])
	}
}

// TestParseAttributes_NonNumericRawSkipped RAW_VALUE 非数值(如 "N/A")必须跳过
// 而不是塞 0。
func TestParseAttributes_NonNumericRawSkipped(t *testing.T) {
	lines := [][]byte{
		[]byte("ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE"),
		[]byte("194 Temperature_Celsius     0x0022   065   055   000    Old_age   Always       -       N/A"),
	}
	got := parseAttributes(lines)
	if _, ok := got.Attrs["Temperature_Celsius"]; ok {
		t.Errorf("RAW_VALUE=N/A 应跳过, got %+v", got.Attrs)
	}
}

// TestParseAttributes_EmptyLines 无属性节时返回空 map(非 nil)。
func TestParseAttributes_EmptyLines(t *testing.T) {
	got := parseAttributes([][]byte{[]byte("smartctl 7.2 ...")})
	if got.Attrs == nil {
		t.Errorf("Attrs 应为空 map, got nil")
	}
	if len(got.Attrs) != 0 {
		t.Errorf("Attrs 应为空: %+v", got.Attrs)
	}
}

// --- 位掩码翻译 ---

// TestTranslateSmartctlBitmask 逐位验证 smartctl 退出码语义映射。
func TestTranslateSmartctlBitmask(t *testing.T) {
	cases := []struct {
		rc   int
		want string
	}{
		{0, ""},
		{1, "bit 0 (Command line did not parse)"},
		{2, "bit 1 (Device open failed / no IDENTIFY / low-power mode)"},
		{4, "bit 2 (SMART or ATA command failed / checksum error)"},
		{8, `bit 3 (SMART status check returned "DISK FAILING")`},
		{16, "bit 4 (Prefail attributes <= threshold)"},
		{32, `bit 5 (SMART status "DISK OK" but attributes were <= threshold in the past)`},
		{64, "bit 6 (Device error log contains records of errors)"},
		{128, "bit 7 (Device self-test log contains records of errors)"},
	}
	for _, c := range cases {
		got := translateSmartctlBitmask(c.rc)
		if got != c.want {
			t.Errorf("translateSmartctlBitmask(%d) = %q\nwant %q", c.rc, got, c.want)
		}
	}
}

// TestTranslateSmartctlBitmask_MultiBits 多位组合逐位列出,用 "; " 连接。
func TestTranslateSmartctlBitmask_MultiBits(t *testing.T) {
	got := translateSmartctlBitmask(1 | 4 | 8) // rc=13
	want := "bit 0 (Command line did not parse); bit 2 (SMART or ATA command failed / checksum error); " +
		`bit 3 (SMART status check returned "DISK FAILING")`
	if got != want {
		t.Errorf("translateSmartctlBitmask(13) = %q\nwant %q", got, want)
	}
}

// TestTranslateSmartctlBitmask_AllBits rc=255 → 8 个位全列。
func TestTranslateSmartctlBitmask_AllBits(t *testing.T) {
	got := translateSmartctlBitmask(255)
	for i := 0; i < 8; i++ {
		if !strings.Contains(got, "bit "+string(rune('0'+i))) {
			t.Errorf("translateSmartctlBitmask(255) 缺 bit %d: %q", i, got)
		}
	}
}

// TestTranslateSmartctlBitmask_NegativeGuard 负数 rc(异常输入)返回空串,
// 不 panic。
func TestTranslateSmartctlBitmask_NegativeGuard(t *testing.T) {
	if got := translateSmartctlBitmask(-1); got != "" {
		t.Errorf("translateSmartctlBitmask(-1) = %q, want \"\"", got)
	}
}

// --- handleExecError ---

// TestHandleExecError_BitmaskNote rc=8+stderr 空 → 位掩码翻译为 note,fatal=false。
func TestHandleExecError_BitmaskNote(t *testing.T) {
	err := &execError{Code: 8, Stderr: "", Cause: errors.New("exit 8")}
	note, bitmask, fatal := handleExecError(err)
	if fatal {
		t.Errorf("rc=8 不应 fatal")
	}
	if bitmask != 8 {
		t.Errorf("bitmask = %d, want 8", bitmask)
	}
	if !strings.Contains(note, "bit 3") {
		t.Errorf("note 缺 bit 3: %q", note)
	}
}

// TestHandleExecError_RealStderrFatal 真 stderr 错(rc=2 + 非空 stderr)→ fatal=true。
// 这是"smartctl 位掩码不 fatal / 真 stderr 才 fatal"的核心裁决。
func TestHandleExecError_RealStderrFatal(t *testing.T) {
	err := &execError{Code: 2, Stderr: "smartctl: cannot open /sys/class/nvme/nvme0", Cause: errors.New("exit 2")}
	_, _, fatal := handleExecError(err)
	if !fatal {
		t.Errorf("真 stderr 错应 fatal")
	}
}

// TestHandleExecError_MissingBinary smartctl 不在 → note + fatal=false。
func TestHandleExecError_MissingBinary(t *testing.T) {
	err := &fs.PathError{Op: "fork", Path: "/usr/sbin/smartctl", Err: fs.ErrNotExist}
	note, bitmask, fatal := handleExecError(err)
	if fatal {
		t.Errorf("缺失 smartctl 不应 fatal")
	}
	if bitmask != 0 {
		t.Errorf("bitmask = %d, want 0", bitmask)
	}
	if !strings.Contains(note, "smartctl 不可用") {
		t.Errorf("note = %q", note)
	}
}

// TestHandleExecError_NonExecErrorFatal 非 execError(ctx.Err / 管道失败)→ fatal。
func TestHandleExecError_NonExecErrorFatal(t *testing.T) {
	for _, err := range []error{
		errors.New("some internal"),
		context.DeadlineExceeded,
	} {
		_, _, fatal := handleExecError(err)
		if !fatal {
			t.Errorf("handleExecError(%v) 应 fatal", err)
		}
	}
}

// TestHandleExecError_NilError nil → 空 note、bitmask=0、fatal=false。
func TestHandleExecError_NilError(t *testing.T) {
	note, bitmask, fatal := handleExecError(nil)
	if note != "" || bitmask != 0 || fatal {
		t.Errorf("nil 错误应全零, got note=%q bitmask=%d fatal=%v", note, bitmask, fatal)
	}
}

// TestHandleExecError_ZeroCodeWithStderr rc=0 + stderr 非空仍视为真 stderr 错。
func TestHandleExecError_ZeroCodeWithStderr(t *testing.T) {
	err := &execError{Code: 0, Stderr: "real error", Cause: errors.New("exit 0")}
	_, _, fatal := handleExecError(err)
	if !fatal {
		t.Errorf("rc=0 + stderr 应 fatal")
	}
}

// --- 服务层(fakeRunner 注入)---

// TestServiceList_ScanThreeDisks `--scan` 三条目 → 3 Disk。
func TestServiceList_ScanThreeDisks(t *testing.T) {
	svc, fr := newFakeService(fakeResult{lines: splitFixture(t, "scan.txt")})
	got, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if fr.calls != 1 {
		t.Errorf("calls = %d, want 1", fr.calls)
	}
	if fr.lastBin != "smartctl-stub" {
		t.Errorf("bin = %q, want smartctl-stub", fr.lastBin)
	}
	if !reflect.DeepEqual(fr.lastArg, []string{"--scan"}) {
		t.Errorf("args = %v, want [--scan]", fr.lastArg)
	}
	if len(got.Disks) != 3 {
		t.Fatalf("Disks = %d, want 3: %+v", len(got.Disks), got.Disks)
	}
	if got.Note != "" {
		t.Errorf("Note 应为空, got %q", got.Note)
	}
}

// TestServiceList_EmptyScan 无磁盘 → Disks 显式 [] 而非 nil。
func TestServiceList_EmptyScan(t *testing.T) {
	svc, _ := newFakeService(fakeResult{lines: nil})
	got, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got.Disks == nil {
		t.Errorf("Disks 应为空 slice 而非 nil")
	}
	if len(got.Disks) != 0 {
		t.Errorf("Disks 应为空: %+v", got.Disks)
	}
}

// TestServiceList_MissingBinary smartctl 缺失 → 空集 + note,fatal=false。
func TestServiceList_MissingBinary(t *testing.T) {
	svc, _ := newFakeService(fakeResult{
		err: &fs.PathError{Op: "fork", Path: "smartctl-stub", Err: fs.ErrNotExist},
	})
	got, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List 不应 fatal: %v", err)
	}
	if len(got.Disks) != 0 {
		t.Errorf("Disks 应为空: %+v", got.Disks)
	}
	if !strings.Contains(got.Note, "smartctl 不可用") {
		t.Errorf("Note = %q", got.Note)
	}
}

// TestServiceList_RealStderrFatal 真 stderr 错 → List 必须上抛(不吞)。
func TestServiceList_RealStderrFatal(t *testing.T) {
	svc, _ := newFakeService(fakeResult{
		err: &execError{Code: 2, Stderr: "smartctl: cannot open /sys/class/nvme", Cause: errors.New("exit 2")},
	})
	_, err := svc.List(context.Background())
	if err == nil {
		t.Fatal("真 stderr 错应上抛")
	}
	if !strings.Contains(err.Error(), "cannot open /sys/class/nvme") {
		t.Errorf("错误应带 stderr: %v", err)
	}
}

// TestServiceHealth_Passed rc=0 + PASSED → Passed=true,ExitBitmask=0。
func TestServiceHealth_Passed(t *testing.T) {
	svc, fr := newFakeService(fakeResult{lines: splitFixture(t, "health-passed.txt")})
	got, err := svc.Health(context.Background(), SmartDiskArgs{Disk: "/dev/sda"})
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !reflect.DeepEqual(fr.lastArg, []string{"-H", "/dev/sda"}) {
		t.Errorf("args = %v, want [-H /dev/sda]", fr.lastArg)
	}
	if !got.Passed {
		t.Errorf("Passed 应 true")
	}
	if got.ExitBitmask != 0 {
		t.Errorf("ExitBitmask = %d, want 0", got.ExitBitmask)
	}
	if got.Note != "" {
		t.Errorf("Note 应为空, got %q", got.Note)
	}
	if got.Disk != "/dev/sda" {
		t.Errorf("Disk = %q", got.Disk)
	}
}

// TestServiceHealth_Failed rc=8 + FAILED → Passed=false,ExitBitmask=8,
// note 含 bit 3。
func TestServiceHealth_Failed(t *testing.T) {
	svc, fr := newFakeService(fakeResult{
		lines: splitFixture(t, "health-failed.txt"),
		err:   &execError{Code: 8, Stderr: "", Cause: errors.New("exit 8")},
	})
	got, err := svc.Health(context.Background(), SmartDiskArgs{Disk: "/dev/sda"})
	if err != nil {
		t.Fatalf("Health 不应 fatal: %v", err)
	}
	_ = fr
	if got.Passed {
		t.Errorf("Passed 应 false")
	}
	if got.ExitBitmask != 8 {
		t.Errorf("ExitBitmask = %d, want 8", got.ExitBitmask)
	}
	if !strings.Contains(got.Note, "bit 3") {
		t.Errorf("Note = %q", got.Note)
	}
}

// TestServiceHealth_Bit3ForcesFailed 文本 PASSED 但 rc bit 3 设 → Passed 必须
// 被钳制为 false(位掩码是权威健康信号)。
func TestServiceHealth_Bit3ForcesFailed(t *testing.T) {
	svc, _ := newFakeService(fakeResult{
		lines: splitFixture(t, "health-passed.txt"),
		err:   &execError{Code: 8, Stderr: "", Cause: errors.New("exit 8")},
	})
	got, err := svc.Health(context.Background(), SmartDiskArgs{Disk: "/dev/sda"})
	if err != nil {
		t.Fatalf("Health 不应 fatal: %v", err)
	}
	if got.Passed {
		t.Errorf("bit 3 设置时 Passed 必须 false(即便文本 PASSED)")
	}
}

// TestServiceHealth_DeviceOpenFailed 位 1 (open failed)→ note 说明、bitmask=2,
// Passed=false。
func TestServiceHealth_DeviceOpenFailed(t *testing.T) {
	svc, _ := newFakeService(fakeResult{
		lines: [][]byte{[]byte("Smartctl open device: /dev/sda failed: Permission denied")},
		err:   &execError{Code: 2, Stderr: "", Cause: errors.New("exit 2")},
	})
	got, err := svc.Health(context.Background(), SmartDiskArgs{Disk: "/dev/sda"})
	if err != nil {
		t.Fatalf("Health 不应 fatal: %v", err)
	}
	if got.Passed {
		t.Errorf("open failed 应 Passed=false")
	}
	if got.ExitBitmask != 2 {
		t.Errorf("ExitBitmask = %d, want 2", got.ExitBitmask)
	}
	if !strings.Contains(got.Note, "bit 1") {
		t.Errorf("Note = %q", got.Note)
	}
}

// TestServiceHealth_InvalidDisk 注入 disk → 立即拒绝,不 fork。
func TestServiceHealth_InvalidDisk(t *testing.T) {
	svc, fr := newFakeService()
	_, err := svc.Health(context.Background(), SmartDiskArgs{Disk: "/dev/sda; cat /etc/passwd"})
	if err == nil {
		t.Fatal("注入应拒绝")
	}
	if fr.calls != 0 {
		t.Errorf("不应 fork, calls=%d", fr.calls)
	}
}

// TestServiceAttributes_ATA ATA 属性 5 关键齐全,argv 是 `-A <disk>`。
func TestServiceAttributes_ATA(t *testing.T) {
	svc, fr := newFakeService(fakeResult{lines: splitFixture(t, "attributes-ata.txt")})
	got, err := svc.Attributes(context.Background(), SmartDiskArgs{Disk: "/dev/sda"})
	if err != nil {
		t.Fatalf("Attributes: %v", err)
	}
	if !reflect.DeepEqual(fr.lastArg, []string{"-A", "/dev/sda"}) {
		t.Errorf("args = %v, want [-A /dev/sda]", fr.lastArg)
	}
	if got.Disk != "/dev/sda" {
		t.Errorf("Disk = %q", got.Disk)
	}
	if got.Vendor != "Samsung based SSDs" {
		t.Errorf("Vendor = %q", got.Vendor)
	}
	if got.Attrs["Temperature_Celsius"] != 35 {
		t.Errorf("Temperature_Celsius = %d, want 35", got.Attrs["Temperature_Celsius"])
	}
	if got.Attrs["Power_On_Hours"] != 8760 {
		t.Errorf("Power_On_Hours = %d, want 8760", got.Attrs["Power_On_Hours"])
	}
}

// TestServiceAttributes_NVMe NVMe 形态。
func TestServiceAttributes_NVMe(t *testing.T) {
	svc, _ := newFakeService(fakeResult{lines: splitFixture(t, "attributes-nvme.txt")})
	got, err := svc.Attributes(context.Background(), SmartDiskArgs{Disk: "/dev/nvme0n1"})
	if err != nil {
		t.Fatalf("Attributes: %v", err)
	}
	if got.Attrs["Temperature_Celsius"] != 35 {
		t.Errorf("Temperature_Celsius = %d", got.Attrs["Temperature_Celsius"])
	}
	if got.Attrs["Power_On_Hours"] != 8760 {
		t.Errorf("Power_On_Hours = %d", got.Attrs["Power_On_Hours"])
	}
}

// TestServiceAttributes_BitmaskNote rc!=0 + stderr 空 → note 但不 fatal。
func TestServiceAttributes_BitmaskNote(t *testing.T) {
	svc, _ := newFakeService(fakeResult{
		lines: splitFixture(t, "attributes-ata.txt"),
		err:   &execError{Code: 2, Stderr: "", Cause: errors.New("exit 2")},
	})
	got, err := svc.Attributes(context.Background(), SmartDiskArgs{Disk: "/dev/sda"})
	if err != nil {
		t.Fatalf("Attributes 不应 fatal: %v", err)
	}
	if !strings.Contains(got.Note, "bit 1") {
		t.Errorf("Note = %q", got.Note)
	}
	if got.Attrs["Power_On_Hours"] != 8760 {
		t.Errorf("位掩码非 fatal 时仍应解析到属性, got %+v", got.Attrs)
	}
}

// TestServiceTest_L1Deferred_NoFork smart_test 不 fork,返回 Started=false
// + L1 deferred note。**这是本批核心裁决**:L1 自检需 y/n 确认令牌,
// 本批不走 daedalus-tx/confirm_token,故不真触发。
func TestServiceTest_L1Deferred_NoFork(t *testing.T) {
	svc, fr := newFakeService()
	got, err := svc.Test(context.Background(), SmartTestArgs{Disk: "/dev/sda", Kind: "short"})
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if fr.calls != 0 {
		t.Errorf("smart_test 不应 fork, calls=%d", fr.calls)
	}
	if got.Started {
		t.Errorf("Started 应 false")
	}
	if got.Disk != "/dev/sda" || got.Kind != "short" {
		t.Errorf("回显错: %+v", got)
	}
	if !strings.Contains(got.Note, "L1") {
		t.Errorf("Note 应含 L1: %q", got.Note)
	}
}

// TestServiceTest_InvalidKind kind 只允许 short|long(严格小写,与 JSON schema
// Enum 语义对齐);其它值拒绝且不 fork。
func TestServiceTest_InvalidKind(t *testing.T) {
	for _, kind := range []string{"full", "SHORT", "conveyance", "--scan", " Short "} {
		svc, fr := newFakeService()
		_, err := svc.Test(context.Background(), SmartTestArgs{Disk: "/dev/sda", Kind: kind})
		if err == nil {
			t.Errorf("kind=%q 应拒绝", kind)
		}
		if fr.calls != 0 {
			t.Errorf("kind=%q 不应 fork", kind)
		}
	}
}

// TestServiceTest_EmptyKindDefaultShort 空 kind 退化为 short。
func TestServiceTest_EmptyKindDefaultShort(t *testing.T) {
	svc, _ := newFakeService()
	got, err := svc.Test(context.Background(), SmartTestArgs{Disk: "/dev/sda"})
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if got.Kind != "short" {
		t.Errorf("Kind = %q, want short", got.Kind)
	}
}

// TestServiceTest_InvalidDisk 注入 disk 同样拒绝。
func TestServiceTest_InvalidDisk(t *testing.T) {
	svc, fr := newFakeService()
	_, err := svc.Test(context.Background(), SmartTestArgs{Disk: "/dev/../etc/passwd", Kind: "short"})
	if err == nil {
		t.Fatal("非法 disk 应拒绝")
	}
	if fr.calls != 0 {
		t.Errorf("不应 fork, calls=%d", fr.calls)
	}
}

// --- 真 exec 贯通 ---

// writeFakeScript 写一个可执行的 shell 假脚本到 tmp 目录,返回绝对路径;
// 与 avc/gpu 同名同语义(不跨插件 import)。
func writeFakeScript(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("写假脚本失败: %v", err)
	}
	return path
}

// TestExecHelper_RealStderrBeforeStart 真 fork:子进程 stdout+stderr 走真管道,
// stderr 必须进 execError.Stderr;若有人把 cmd.Stderr = &stderr 挪到
// cmd.Start() 之后,Stderr 必空、本测试失败 —— 锁住"stderr 在 Start 前接"。
func TestExecHelper_RealStderrBeforeStart(t *testing.T) {
	path := writeFakeScript(t, "fake-smartctl", "#!/bin/sh\necho SMART_STDERR_MARKER 1>&2\nexit 2\n")
	got := execHelper(context.Background(), path, nil, func([]byte) bool { return true }, "-H", "/dev/sda")
	if got == nil {
		t.Fatal("rc=2 应返回 execError")
	}
	var ee *execError
	if !errors.As(got, &ee) {
		t.Fatalf("err 应为 *execError, got %T: %v", got, got)
	}
	if ee.Code != 2 {
		t.Errorf("Code=%d, want 2", ee.Code)
	}
	if !strings.Contains(ee.Stderr, "SMART_STDERR_MARKER") {
		t.Errorf("Stderr 应含真子进程 stderr 内容: %q", ee.Stderr)
	}
}

// TestExecHelper_RealRc0StdoutCaptured rc=0 时 stdout 逐行回传,stderr 为空。
func TestExecHelper_RealRc0StdoutCaptured(t *testing.T) {
	path := writeFakeScript(t, "fake-smartctl", "#!/bin/sh\nfor i in 1 2 3; do echo \"line $i\"; done\n")
	var got []string
	err := execHelper(context.Background(), path, nil, func(b []byte) bool {
		got = append(got, string(b))
		return true
	}, "--scan")
	if err != nil {
		t.Fatalf("rc=0 不应报错: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("捕获行 = %d, want 3: %v", len(got), got)
	}
}

// TestExecHelper_RealRcBitmaskTranslation 真 fork + 位掩码 rc=8(stderr 空)→
// handleExecError 必须翻译为 bit 3 note,fatal=false,贯通到 Health。
func TestExecHelper_RealRcBitmaskTranslation(t *testing.T) {
	path := writeFakeScript(t, "fake-smartctl",
		"#!/bin/sh\necho 'SMART overall-health self-assessment test result: PASSED'\nexit 8\n")

	svc := &service{run: execHelper, timeout: smartTimeout, binary: path}
	got, err := svc.Health(context.Background(), SmartDiskArgs{Disk: "/dev/sda"})
	if err != nil {
		t.Fatalf("位掩码 rc=8 不应 fatal: %v", err)
	}
	if got.Passed {
		t.Errorf("bit 3 设置时 Passed 必须 false")
	}
	if got.ExitBitmask != 8 {
		t.Errorf("ExitBitmask = %d, want 8", got.ExitBitmask)
	}
	if !strings.Contains(got.Note, "bit 3") {
		t.Errorf("Note = %q", got.Note)
	}
}

// TestHealth_RealStderrFatal 真 fork + rc=2 + 真 stderr → handleExecError 判
// fatal,stderr 经 wrap 出现在 err.Error()(承接 Task 3 stderr 教训)。
func TestHealth_RealStderrFatal(t *testing.T) {
	path := writeFakeScript(t, "fake-smartctl",
		"#!/bin/sh\necho SMART_STDERR_MARKER 1>&2\nexit 2\n")

	svc := &service{run: execHelper, timeout: smartTimeout, binary: path}

	_, err := svc.Health(context.Background(), SmartDiskArgs{Disk: "/dev/sda"})
	if err == nil {
		t.Fatal("rc=2+真 stderr 应 fatal")
	}
	if !strings.Contains(err.Error(), "SMART_STDERR_MARKER") {
		t.Errorf("错误链未带真子进程 stderr: %v", err)
	}
}

// TestExecHelper_RealMissingBinary 真 fork:binary 缺失应 wrap 为 fs.ErrNotExist,
// handleExecError 降级为 note。
func TestExecHelper_RealMissingBinary(t *testing.T) {
	got := execHelper(context.Background(), "/nonexistent/fake-smartctl", nil,
		func([]byte) bool { return true }, "--scan")
	if got == nil {
		t.Fatal("缺失 binary 应报错")
	}
	if !isMissingBinary(got) {
		t.Errorf("应识别为 missing binary: %v", got)
	}
}

// TestExecHelper_RealCtxDeadline ctx 到期优先返回 ctx.Err()(DeadlineExceeded)。
func TestExecHelper_RealCtxDeadline(t *testing.T) {
	path := writeFakeScript(t, "fake-smartctl", "#!/bin/sh\nexec sleep 5\n")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got := execHelper(ctx, path, nil, func([]byte) bool { return true }, "--scan")
	if !errors.Is(got, context.DeadlineExceeded) {
		t.Errorf("ctx 到期应返回 DeadlineExceeded, got %v", got)
	}
}
