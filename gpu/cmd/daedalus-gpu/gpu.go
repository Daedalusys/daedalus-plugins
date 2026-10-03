// gpu 只读基元:并联 NVIDIA(nvidia-smi)/ AMD(rocm-smi)/ Intel(intel_gpu_top)
// 三厂商 CLI,把遥测对齐到统一的 GPUInfo / ProcessInfo / MemoryBlock 载荷。
//
// 与家族其它 CLI-fork 克隆的差异:
//   - **可选依赖**:每厂商启动前 exec.LookPath 探测,缺即"跳过该厂商"而非报错;
//     三厂商全缺时返回空集 + 显式 note,不视为致命故障。
//   - **同名异义字段**:Utilization / Temperature / Memory*/Power 在不同厂商语义
//     不同(NVIDIA=SM%、AMD=GFX%、Intel=Render/3D 繁忙度;功耗均值口径也不同),
//     已在载荷字段注释与工具描述里逐字段标注单位/语义差异,禁止跨厂商聚合计算。
//   - **AMD/Intel 覆盖未真机验证**:夹具来自上游 CLI 文档与 rocm-smi 源码常量
//     字面量,与真机可能有键名/单位漂移,见各 vendor 函数头注释。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 三厂商二进制绝对路径;包级变量便于测试注入假脚本/替身。
var (
	nvidiaSmiBin   = "/usr/bin/nvidia-smi"
	rocmSmiBin     = "/usr/bin/rocm-smi"
	intelGpuTopBin = "/usr/bin/intel_gpu_top"
)

// 厂商标识(与 manifest 工具描述、schema 标注保持一致)。
const (
	vendorNVIDIA = "nvidia"
	vendorAMD    = "amd"
	vendorIntel  = "intel"
)

// gpuTimeout 是单厂商 CLI 的兜底超时;nvidia-smi 通常 <1s,rocm-smi /
// intel_gpu_top 因库初始化可能 1~2s,30s 上限覆盖冷启动。
const gpuTimeout = 30 * time.Second

// --- 可移植 runner(core,与 avc.go 的"可移植 runner(core)"块对齐)---

// execError 是 CLI 非零退出的类型化包装:Code 是子进程真实退出码,Stderr 是
// 子进程 stderr 内容。调用方可用 errors.As 取出 Code 决定按"可选依赖缺失"
// / "暂无数据" 语义还是真故障上抛。
type execError struct {
	Code   int    // 子进程退出码(> 0)
	Stderr string // 子进程 stderr 内容(可能为空)
	Cause  error  // 底层错误
}

func (e *execError) Error() string {
	return fmt.Sprintf("CLI 退出码 %d: %s", e.Code, strings.TrimSpace(e.Stderr))
}

func (e *execError) Unwrap() error { return e.Cause }

// isMissingBinary 识别"binary 不在"的 ENOENT 降级信号。
func isMissingBinary(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, exec.ErrNotFound)
}

// mergeNotes 合并非空 note;空串跳过,重复同串去重,其余以 "; " 连接。
// 多厂商降级/部分数据丢弃的拼接入口,避免每次手写 strings.TrimSpace+Join 漂移。
func mergeNotes(notes ...string) string {
	var kept []string
	for _, n := range notes {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		dup := false
		for _, k := range kept {
			if k == n {
				dup = true
				break
			}
		}
		if !dup {
			kept = append(kept, n)
		}
	}
	return strings.Join(kept, "; ")
}

// execHelper 通用 fork 包装:绝对路径 argv 直发(绝不经过 sh -c),逐行把 stdout
// 喂给 onLine。stdin 二选一:nil 时子进程不接 stdin。onLine 返回 false 时杀子
// 进程并正常收工(用作"采集首个样本即收工",见 intel_gpu_top 一次性采集)。
// stderr 必须在 cmd.Start() 之前接好(承接 journal/integrity/triage 教训:
// Start 前不接,stderr 永远空)。
//
// 退出码语义:
//   - ctx 超时/取消:优先返回 ctx.Err()(DeadlineExceeded / Canceled)。
//   - 任意非零退出:stderr wrap 上抛(envelope 形式:execError{Code,Stderr,Cause})。
//   - run 内部不再加超时:调用方用 context.WithTimeout 派生 execCtx。
func execHelper(ctx context.Context, bin string, stdin io.Reader, onLine func([]byte) bool, args ...string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = stdin
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%s stdout 管道失败: %w", bin, err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		if isMissingBinary(err) {
			return err
		}
		return fmt.Errorf("%s 启动失败: %w", bin, err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		if !onLine(scanner.Bytes()) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil
		}
	}
	scanErr := scanner.Err()
	waitErr := cmd.Wait()

	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if scanErr != nil {
		return fmt.Errorf("%s 读取失败: %w", bin, scanErr)
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			code := exitErr.ExitCode()
			if code != 0 {
				return &execError{Code: code, Stderr: stderr.String(), Cause: waitErr}
			}
		}
		return fmt.Errorf("%s 失败: %w(%s)", bin, waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// runCLI 是无 stdin 形态的可移植便捷入口(stdin 恒 nil)。gpu 四工具全部
// 无 stdin 形态,统一走 runCLI。
func runCLI(ctx context.Context, bin string, onLine func([]byte) bool, args ...string) error {
	return execHelper(ctx, bin, nil, onLine, args...)
}

// --- 可选依赖探测 ---

// probeFunc 判定绝对路径 binary 是否可用;默认实现 exec.LookPath,测试可注入。
type probeFunc func(bin string) bool

// probeExists 是生产默认探针:绝对路径在 PATH 之外也能被 LookPath 命中
// (LookPath 对绝对路径直接检查可执行位)。
func probeExists(bin string) bool {
	if bin == "" {
		return false
	}
	_, err := exec.LookPath(bin)
	return err == nil
}

// --- 载荷类型 ---
//
// 同名异义标注约定:字段注释同时记录 NVIDIA / AMD / Intel 三家的实际语义与
// 单位,调用方跨厂商比较时必须带上 Vendor 前缀判断,禁止直接数值对比。

// GPUInfo 是 gpu_list / gpu_status 的统一载荷。不同厂商的同名字段语义不同,
// 详见每字段注释;数值字段全部指针化,厂商未暴露即留 null,不伪造 0 值。
type GPUInfo struct {
	// Index 是插件内全局序号(0 起),按 NVIDIA→AMD→Intel 探测顺序铺开。
	// 厂商内部序号不对外暴露;需要稳定定位请用 (Vendor, Name) 双键。
	Index int `json:"index"`

	// Vendor 是厂商标识:"nvidia" | "amd" | "intel"。
	Vendor string `json:"vendor"`

	// Name 是型号字符串(NVIDIA=name;AMD=Card series/Tag SKU;Intel=devname)。
	Name string `json:"name"`

	// Driver 是驱动版本(NVIDIA=driver_version;AMD=Driver version;Intel=未暴露→空)。
	Driver string `json:"driver"`

	// Temperature 是摄氏度(°C)。
	//   - NVIDIA: temperature.gpu(核心温度)
	//   - AMD: "Temperature (Sensor edge) (C)"(边缘结温;junction/memory 另行报)
	//   - Intel: intel_gpu_top 未暴露 → null
	Temperature *float64 `json:"temperature"`

	// Utilization 是繁忙度百分比(0-100),**同名异义核心字段**:
	//   - NVIDIA: SM%(流式多处理器占用)
	//   - AMD: GFX%(图形管线繁忙度,不含独立 SDMA/VCN 引擎)
	//   - Intel: Render/3D 引擎 busy%(Blitter/Video/VideoEnhance 另行统计)
	// 跨厂商比较必须先看 Vendor;未暴露 → null。
	Utilization *float64 `json:"utilization"`

	// MemoryTotal / MemoryUsed / MemoryFree 是显存(单位 MiB)。
	//   - NVIDIA: memory.{total,used,free} 的 MiB 原值
	//   - AMD: VRAM {Total,Used} Memory(B)字节 ÷ 1024²;free 由 total-used 推导
	//   - Intel: intel_gpu_top 未暴露 → 全 null
	MemoryTotal *float64 `json:"memory_total"`
	MemoryUsed  *float64 `json:"memory_used"`
	MemoryFree  *float64 `json:"memory_free"`

	// Power 是功耗(单位 W),**同名异义**:
	//   - NVIDIA: power.draw(采样点瞬时值)
	//   - AMD: Average Graphics Package Power(采样窗口均值)
	//   - Intel: 未暴露 → null
	Power *float64 `json:"power"`
}

// ProcessInfo 是 gpu_processes 的载荷。AMD/Intel 的 CLI 只给出"PID 占用 N 个
// GPU"而不给出索引,此时 GPUIndices 留空 + Note 说明。
type ProcessInfo struct {
	// PID 是进程号(NVIDIA / AMD 均直接给出)。
	PID int `json:"pid"`

	// Name 是进程名(NVIDIA=process_name;AMD=KFD PROCESS NAME;Intel=client 名)。
	Name string `json:"name"`

	// Vendor 是厂商标识,语义同 GPUInfo.Vendor。
	Vendor string `json:"vendor"`

	// GPUIndices 是厂商内 GPU 序号列表(对应 GPUInfo.Index 的全局序号)。
	// 空表示该厂商 CLI 未给出映射,详见 Note。
	GPUIndices []int `json:"gpu_indices"`

	// MemoryMiB 是该进程占用的显存(MiB);NVIDIA=used_memory;AMD=VRAM USED(字节 ÷ 1024²);
	// Intel=未暴露 → null。
	MemoryMiB *float64 `json:"memory_mib"`

	// Note 是单条进程级别的备注(可选)。
	Note string `json:"note,omitempty"`
}

// MemoryBlock 是 gpu_memory 的单设备载荷。
type MemoryBlock struct {
	// Index / Vendor 对应 GPUInfo 的同名字段(全局序号与厂商)。
	Index  int    `json:"index"`
	Vendor string `json:"vendor"`

	// TotalMiB / UsedMiB / FreeMiB 是显存(单位 MiB);未能读到时为 0,以
	// HasMemory 标识是否有效(避免"0 MiB"与"未知"混淆)。
	HasMemory bool    `json:"has_memory"`
	TotalMiB  float64 `json:"total_mib"`
	UsedMiB   float64 `json:"used_mib"`
	FreeMiB   float64 `json:"free_mib"`

	// Processes 是占用该 GPU 的进程(厂商可映射时才填)。
	Processes []ProcessInfo `json:"processes"`
}

// GPUListResult 是 gpu_list 的载荷(gpus 只填身份字段)。
type GPUListResult struct {
	GPUs []GPUInfo `json:"gpus"`
	Note string    `json:"note"`
}

// GPUStatusResult 是 gpu_status 的载荷(gpus 含全部测量字段)。
type GPUStatusResult struct {
	GPUs []GPUInfo `json:"gpus"`
	Note string    `json:"note"`
}

// GPUProcessesResult 是 gpu_processes 的载荷。
type GPUProcessesResult struct {
	Processes []ProcessInfo `json:"processes"`
	Note      string        `json:"note"`
}

// GPUMemoryResult 是 gpu_memory 的载荷。
type GPUMemoryResult struct {
	Devices []MemoryBlock `json:"devices"`
	Note    string        `json:"note"`
}

// --- service ---

// execRunner 是可注入的 CLI 执行函数(默认 runCLI)。
type execRunner func(ctx context.Context, bin string, stdin io.Reader, onLine func([]byte) bool, args ...string) error

// service 持有 runner / probe / 兜底超时;测试可全注入替身。
type service struct {
	run     execRunner
	probe   probeFunc
	timeout time.Duration
}

// newService 装配生产 service(run=execHelper,probe=exec.LookPath,gpuTimeout 兜底)。
func newService() *service {
	return &service{run: execHelper, probe: probeExists, timeout: gpuTimeout}
}

// runVendor 在 30s 超时上下文中调用厂商 CLI,统一 onLine 收集与错误语义。
func (s *service) runVendor(ctx context.Context, bin string, onLine func([]byte) bool, args ...string) error {
	execCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return s.run(execCtx, bin, nil, onLine, args...)
}

// vendorBundle 是单厂商采集结果(Index/GPUIndices 均为厂商内序号,
// 后续 merge 全局化)。note 记录该厂商的降级原因,不丢到最终 note。
type vendorBundle struct {
	vendor  string
	gpus    []GPUInfo
	procs   []ProcessInfo
	note    string
	skipped bool  // true = 该厂商未启用(probe 失败)或调用中降级
	fatal   error // 真故障(退出码 ≥2 / 非 execError),由调用方决定是否上抛
}

// collect 按 NVIDIA→AMD→Intel 顺序逐厂商探测并采集;probe 失败 → skipped 且
// note 填"跳过该厂商"文案;CLI 失败按 handleVendorError 分流。
func (s *service) collect(ctx context.Context) ([]vendorBundle, error) {
	targets := []struct {
		vendor string
		bin    string
		probe  func(context.Context) (vendorBundle, error)
	}{
		{vendorNVIDIA, nvidiaSmiBin, s.nvidiaProbe},
		{vendorAMD, rocmSmiBin, s.amdProbe},
		{vendorIntel, intelGpuTopBin, s.intelProbe},
	}
	var out []vendorBundle
	for _, t := range targets {
		if !s.probe(t.bin) {
			out = append(out, vendorBundle{
				vendor:  t.vendor,
				skipped: true,
				note:    vendorMissingNote(t.vendor, t.bin),
			})
			continue
		}
		b, err := t.probe(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, b)
	}
	return out, nil
}

// vendorMissingNote 构造"该厂商 CLI 缺失"的降级文案。
func vendorMissingNote(vendor, bin string) string {
	return fmt.Sprintf("%s 不可用(%s 缺失或不可执行),已跳过该厂商", vendor, bin)
}

// handleVendorError 把厂商 CLI 的 execError 分类为"空数据/无匹配"的 note
// (非致命)或真故障(致命)。**本函数是 gpu 自己的退出码判定,不要用 avc 的
// handleExecError**(ausearch 专属,依赖 `<no matches>` 文案)。
//
// 退出码语义(见报告"三厂商退出码实证"):
//   - NVIDIA `nvidia-smi --query-*`:0=正常;1=无设备/查询失败("No devices
//     were found" / "NVIDIA-SMI has failed");≥2=驱动不可用/版本不匹配等真故障。
//   - AMD `rocm-smi`:0=正常(即使 "WARNING: No AMD GPUs specified");1=空集
//     或 concise 输出被拒("ERROR: Cannot print JSON/CSV output for concise
//     output");2=argparse usage 拒绝(真故障,argv 错误)。
//   - Intel `intel_gpu_top`:0=正常(采到样本);≥1=设备/权限错误(未暴露具体
//     语义,保守按致命,报告标注未真机验证)。
func handleVendorError(vendor string, err error) (note string, fatal bool) {
	if err == nil {
		return "", false
	}
	if isMissingBinary(err) {
		return vendorMissingNote(vendor, "(运行期 ENOENT)"), false
	}
	var ee *execError
	if !errors.As(err, &ee) {
		// 非 execError(如 ctx.Err() / 管道失败):真故障上抛。
		return "", true
	}
	switch vendor {
	case vendorNVIDIA:
		// rc=1 + "No devices were found" → 合法空集
		if ee.Code == 1 && strings.Contains(ee.Stderr, "No devices were found") {
			return "nvidia-smi: 未发现 NVIDIA 设备", false
		}
		return "", true
	case vendorAMD:
		// rocm-smi rc=1 + "No AMD GPUs" → 合法空集(无 AMD GPU 的开发机常态)
		if ee.Code == 1 && (strings.Contains(ee.Stderr, "No AMD GPUs") ||
			strings.Contains(ee.Stderr, "Cannot print JSON/CSV output for concise output")) {
			return "rocm-smi: 无 AMD GPU 或 concise 输出被拒,已按空集降级", false
		}
		return "", true
	case vendorIntel:
		// intel_gpu_top 未真机验证;rc≥1 保守按致命,报告标注
		return "", true
	}
	return "", true
}

// --- NVIDIA 适配器 ---
//
// 数据源:nvidia-smi --query-gpu=... / --query-compute-apps=... CSV noheader。
// 夹具来自 NVIDIA 文档(nvidia-smi 主手册)定义的列序与 nounits 单位语义;
// 真机上未运行(nvidia-smi 未预装在开发机)。键位漂移风险:CSV 列数变更会
// 被 parseCSVLenSafe 拒绝,防止静默错位。

// nvidiaQueryColumns 是 gpu_list/gpu_status 的 nvidia-smi 查询列(NVIDIA 文档定义的
// 稳定键名,序号固定);nounits 去掉单位后解析为 float64。
var nvidiaQueryColumns = []string{
	"index", "uuid", "name", "driver_version",
	"temperature.gpu", "utilization.gpu",
	"memory.total", "memory.used", "memory.free",
	"power.draw",
}

// nvidiaProcColumns 是 gpu_processes 的 nvidia-smi 查询列。
var nvidiaProcColumns = []string{"gpu_uuid", "pid", "process_name", "used_memory"}

// nvidiaValue 允许 N/A / Not Supported 等非数值占位。
var nvidiaValuePlaceholder = map[string]bool{
	"[N/A]":                      true,
	"[Not Supported]":            true,
	"[Insufficient Permissions]": true,
	"n/a":                        true,
	"N/A":                        true,
	"":                           true,
}

// parseNvidiaFloat 解析 nvidia-smi --format=csv,noheader,nounits 的单个数值;
// 占位符返回 nil(字段留空)。
func parseNvidiaFloat(s string) *float64 {
	s = strings.TrimSpace(s)
	if nvidiaValuePlaceholder[s] {
		return nil
	}
	// 去掉可能残余的单位后缀(如 "65.32 W"),nounits 下一般不会出现,防御性。
	s = strings.TrimSuffix(s, " W")
	s = strings.TrimSuffix(s, " MiB")
	s = strings.TrimSuffix(s, "%")
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &v
}

// parseNvidiaRow 用 encoding/csv 解析一行(NVIDIA name 可能含逗号,必须走 csv)。
// nvidia-smi 的 CSV 输出是", "(逗号+空格)分隔且字段可带前导空格,需要
// TrimLeadingSpace + LazyQuotes 才能稳住带引号的 name 列。
func parseNvidiaRow(line string) ([]string, error) {
	r := csv.NewReader(strings.NewReader(line))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	rec, err := r.Read()
	if err != nil {
		return nil, err
	}
	for i := range rec {
		rec[i] = strings.TrimSpace(rec[i])
	}
	return rec, nil
}

// nvidiaProbe 拉取 nvidia-smi --query-gpu + --query-compute-apps,组装 vendorBundle。
func (s *service) nvidiaProbe(ctx context.Context) (vendorBundle, error) {
	b := vendorBundle{vendor: vendorNVIDIA}

	// GPU 清单与测量
	var gpuLines []string
	args := []string{
		"--query-gpu=" + strings.Join(nvidiaQueryColumns, ","),
		"--format=csv,noheader,nounits",
	}
	err := s.runVendor(ctx, nvidiaSmiBin, func(line []byte) bool {
		gpuLines = append(gpuLines, string(line))
		return true
	}, args...)
	if note, fatal := handleVendorError(vendorNVIDIA, err); fatal {
		return b, fmt.Errorf("nvidia-smi --query-gpu 失败: %w", err)
	} else if note != "" {
		b.note = note
		b.skipped = true
		return b, nil
	}

	uuidToIdx := map[string]int{}
	for _, line := range gpuLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rec, err := parseNvidiaRow(line)
		if err != nil || len(rec) < len(nvidiaQueryColumns) {
			// 列数漂移 / CSV 损坏:跳过该行并在 note 标注。
			b.note = mergeNotes(b.note, "nvidia-smi 输出列漂移,已跳过无法解析的行")
			continue
		}
		idx64, err := strconv.Atoi(strings.TrimSpace(rec[0]))
		if err != nil {
			b.note = mergeNotes(b.note, "nvidia-smi index 非整数,已跳过")
			continue
		}
		info := GPUInfo{
			Index:       idx64,
			Vendor:      vendorNVIDIA,
			Name:        rec[2],
			Driver:      rec[3],
			Temperature: parseNvidiaFloat(rec[4]),
			Utilization: parseNvidiaFloat(rec[5]),
			MemoryTotal: parseNvidiaFloat(rec[6]),
			MemoryUsed:  parseNvidiaFloat(rec[7]),
			MemoryFree:  parseNvidiaFloat(rec[8]),
			Power:       parseNvidiaFloat(rec[9]),
		}
		uuid := strings.TrimSpace(rec[1])
		if uuid != "" {
			uuidToIdx[uuid] = idx64
		}
		b.gpus = append(b.gpus, info)
	}

	// 计算/图形进程
	var procLines []string
	pargs := []string{
		"--query-compute-apps=" + strings.Join(nvidiaProcColumns, ","),
		"--format=csv,noheader,nounits",
	}
	perr := s.runVendor(ctx, nvidiaSmiBin, func(line []byte) bool {
		procLines = append(procLines, string(line))
		return true
	}, pargs...)
	if note, fatal := handleVendorError(vendorNVIDIA, perr); fatal {
		return b, fmt.Errorf("nvidia-smi --query-compute-apps 失败: %w", perr)
	} else if note != "" {
		b.note = mergeNotes(b.note, note)
	}

	for _, line := range procLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rec, err := parseNvidiaRow(line)
		if err != nil || len(rec) < len(nvidiaProcColumns) {
			b.note = mergeNotes(b.note, "nvidia-smi 进程查询输出列漂移,已跳过无法解析的行")
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(rec[1]))
		if err != nil {
			continue
		}
		pi := ProcessInfo{
			PID:        pid,
			Name:       rec[2],
			Vendor:     vendorNVIDIA,
			GPUIndices: []int{},
			MemoryMiB:  parseNvidiaFloat(rec[3]),
		}
		if gidx, ok := uuidToIdx[strings.TrimSpace(rec[0])]; ok {
			pi.GPUIndices = []int{gidx}
		}
		b.procs = append(b.procs, pi)
	}
	return b, nil
}

// --- AMD 适配器 ---
//
// 数据源:rocm-smi --json(读 card<idx> 键位)+ --showpids(进程表)。
// 键位/单位依据 rocm-smi 1.4.x 的 printLog / print2DArray 源码常量(见
// /usr/bin/rocm-smi:printLog('GPU use (%)' / 'VRAM Total Memory (B)' /
// 'Average Graphics Package Power (W)' / 'Temperature (Sensor %s) (C)')。
// **未真机验证**:开发机 rocm-smi 装了但无 AMD GPU,JSON 骨架仅 "system" 段,
// 真机卡内键名/单位可能有漂移。

// amdMetricsKey 从 rocm-smi 单卡 JSON 键值对里挑出"最贴近语义"的测量值。
// 温度优先 Sensor edge,退而 Sensor junction,再退而 Sensor memory。
var amdTemperatureOrder = []string{
	"Temperature (Sensor edge) (C)",
	"Temperature (Sensor junction) (C)",
	"Temperature (Sensor memory) (C)",
}

// amdCardKeyPattern 是 rocm-smi 卡键位 "card<N>"。
var amdCardKeyPattern = regexp.MustCompile(`^card(\d+)$`)

// amdProcKeyPattern 是 rocm-smi --showpids --json 的进程键位 "PID<pid>"。
var amdProcKeyPattern = regexp.MustCompile(`^PID(\d+)$`)

// bytesToMiB 把字节换算为 MiB(AMD VRAM 原生单位是 B)。
func bytesToMiB(b float64) float64 { return b / (1024 * 1024) }

// parseAMDNumber 解析 rocm-smi 值字段;非数值占位("N/A"、"Unsupported"、
// "0.0" 也算数值)一律返回 nil。
func parseAMDNumber(s string) *float64 {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "N/A") || strings.Contains(s, "Unsupported") ||
		strings.Contains(s, "Not Supported") {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &v
}

// amdProbe 拉取 rocm-smi --json 的卡测量 + --showpids 的进程表。
func (s *service) amdProbe(ctx context.Context) (vendorBundle, error) {
	b := vendorBundle{vendor: vendorAMD}

	// 1) 卡测量
	var buf bytes.Buffer
	args := []string{
		"--showproductname", "--showdriverversion",
		"--showtemp", "--showuse", "--showmeminfo", "vram", "--showpower",
		"--json",
	}
	err := s.runVendor(ctx, rocmSmiBin, func(line []byte) bool {
		buf.Write(line)
		buf.WriteByte('\n')
		return true
	}, args...)
	if note, fatal := handleVendorError(vendorAMD, err); fatal {
		return b, fmt.Errorf("rocm-smi --json 失败: %w", err)
	} else if note != "" {
		b.note = note
		b.skipped = true
		return b, nil
	}

	var raw map[string]map[string]string
	if jerr := json.Unmarshal(buf.Bytes(), &raw); jerr != nil {
		b.note = "rocm-smi JSON 解析失败,已按空集降级"
		b.skipped = true
		return b, nil
	}

	systemBlock := raw["system"]
	driver := ""
	if systemBlock != nil {
		driver = systemBlock["Driver version"]
	}

	// 卡序稳定:NVIDIA→AMD→Intel 顺序已由 collect 固定;AMD 内部按 card<N> 数字升序。
	cardKeys := make([]string, 0, len(raw))
	for k := range raw {
		if k == "system" {
			continue
		}
		if m := amdCardKeyPattern.FindStringSubmatch(k); m != nil {
			cardKeys = append(cardKeys, k)
		}
	}
	sort.Slice(cardKeys, func(i, j int) bool {
		return amdCardIndex(cardKeys[i]) < amdCardIndex(cardKeys[j])
	})

	for _, ck := range cardKeys {
		block := raw[ck]
		idx := amdCardIndex(ck)
		info := GPUInfo{
			Index:       idx,
			Vendor:      vendorAMD,
			Driver:      driver,
			MemoryTotal: parseAMDNumber(block["VRAM Total Memory (B)"]),
			MemoryUsed:  parseAMDNumber(block["VRAM Total Used Memory (B)"]),
		}
		// 名称:Card series 优先,退而 Card model,再退而 Card vendor。
		info.Name = pickFirstNonEmpty(block, "Card series", "Card model", "Card vendor", "Card SKU")
		// 温度:按 amdTemperatureOrder 挑第一个有读数的传感器。
		for _, k := range amdTemperatureOrder {
			if v := parseAMDNumber(block[k]); v != nil {
				info.Temperature = v
				break
			}
		}
		info.Utilization = parseAMDNumber(block["GPU use (%)"])
		info.Power = parseAMDNumber(block["Average Graphics Package Power (W)"])
		// 单位换算:rocm-smi 显存单位是字节。
		if info.MemoryTotal != nil {
			m := bytesToMiB(*info.MemoryTotal)
			info.MemoryTotal = &m
		}
		if info.MemoryUsed != nil {
			m := bytesToMiB(*info.MemoryUsed)
			info.MemoryUsed = &m
		}
		if info.MemoryTotal != nil && info.MemoryUsed != nil {
			free := *info.MemoryTotal - *info.MemoryUsed
			if free < 0 {
				free = 0
			}
			info.MemoryFree = &free
		}
		b.gpus = append(b.gpus, info)
	}

	// 2) 进程(rocm-smi --showpids --json:system 块键 PID<N> → 5 字段 CSV)
	pargs := []string{"--showpids", "--json"}
	var pbuf bytes.Buffer
	perr := s.runVendor(ctx, rocmSmiBin, func(line []byte) bool {
		pbuf.Write(line)
		pbuf.WriteByte('\n')
		return true
	}, pargs...)
	if note, fatal := handleVendorError(vendorAMD, perr); fatal {
		return b, fmt.Errorf("rocm-smi --showpids 失败: %w", perr)
	} else if note != "" {
		b.note = mergeNotes(b.note, note)
	}
	b.procs = parseAMDProcesses(pbuf.Bytes(), &b)

	return b, nil
}

// amdCardIndex 从 "card<N>" 抽数字索引;非法键返回 -1 但调用方已按正则过滤。
func amdCardIndex(k string) int {
	m := amdCardKeyPattern.FindStringSubmatch(k)
	if m == nil {
		return -1
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return -1
	}
	return n
}

// pickFirstNonEmpty 依序取第一个非空字符串键值。
func pickFirstNonEmpty(block map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := block[k]; ok {
			v = strings.TrimSpace(v)
			if v != "" && !strings.Contains(v, "N/A") {
				return v
			}
		}
	}
	return ""
}

// parseAMDProcesses 解析 rocm-smi --showpids --json 的 system 块:
// 键 "PID<N>",值 "process-name, GPU(s), VRAM USED, SDMA USED, CU OCCUPANCY"
// (rocm-smi print2DArray 在 JSON 模式下把表头丢进 system,行打成 CSV 字符串)。
//
// ⚠ AMD --showpids 只给"占用 GPU 数"而非索引,故 GPUIndices 恒为空 + Note 说明。
func parseAMDProcesses(data []byte, b *vendorBundle) []ProcessInfo {
	var raw map[string]map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		b.note = mergeNotes(b.note, "rocm-smi --showpids JSON 解析失败,已按空集降级")
		return nil
	}
	sysBlock := raw["system"]
	if sysBlock == nil {
		return nil
	}
	pids := make([]int, 0, len(sysBlock))
	byPID := map[int]ProcessInfo{}
	for k, v := range sysBlock {
		m := amdProcKeyPattern.FindStringSubmatch(k)
		if m == nil {
			continue
		}
		pid, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		fields := strings.Split(v, ",")
		name := ""
		if len(fields) > 0 {
			name = strings.TrimSpace(fields[0])
		}
		pi := ProcessInfo{
			PID:        pid,
			Name:       name,
			Vendor:     vendorAMD,
			GPUIndices: []int{},
			Note:       "AMD rocm-smi --showpids 仅给占用 GPU 数量,未给索引,GPUIndices 留空",
		}
		// VRAM USED(字段 3,B)换算 MiB。
		if len(fields) >= 3 {
			if mb := parseAMDNumber(strings.TrimSpace(fields[2])); mb != nil {
				mib := bytesToMiB(*mb)
				pi.MemoryMiB = &mib
			}
		}
		byPID[pid] = pi
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	out := make([]ProcessInfo, 0, len(pids))
	for _, pid := range pids {
		out = append(out, byPID[pid])
	}
	return out
}

// --- Intel 适配器 ---
//
// 数据源:intel_gpu_top -J -s <ms>(JSON 每个采样一行,持续输出;采集首样本即
// 杀进程)。**未真机验证**:开发机无 Intel GPU 也没有 intel_gpu_top,输出结构
// 依据上游 intel-gpu-tools 的 JSON writer 定义;字段名/嵌套可能随版本漂移。
// Intel 未暴露 VRAM 总量/温度/功耗 → 相关字段留 null,工具描述里已标注。

// intelProbe 拉取 intel_gpu_top -J -s 1000 的首个 JSON 样本并解析。
func (s *service) intelProbe(ctx context.Context) (vendorBundle, error) {
	b := vendorBundle{vendor: vendorIntel}

	var lines []string
	err := s.runVendor(ctx, intelGpuTopBin, func(line []byte) bool {
		l := strings.TrimSpace(string(line))
		if l == "" {
			return true
		}
		lines = append(lines, l)
		// intel_gpu_top -J 每个采样一行 JSON;抓到首个非空行即停(kill 子进程)。
		return false
	}, "-J", "-s", "1000")
	if note, fatal := handleVendorError(vendorIntel, err); fatal {
		return b, fmt.Errorf("intel_gpu_top -J 失败: %w", err)
	} else if note != "" {
		b.note = note
		b.skipped = true
		return b, nil
	}

	if len(lines) == 0 {
		b.note = "intel_gpu_top 未采到样本,已按空集降级"
		b.skipped = true
		return b, nil
	}

	var sample map[string]json.RawMessage
	if err := json.Unmarshal([]byte(lines[0]), &sample); err != nil {
		b.note = "intel_gpu_top JSON 解析失败,已按空集降级"
		b.skipped = true
		return b, nil
	}

	// Eng:{"Render/3D/0": {"busy": 12.3, ...}, "Blitter/0": {...}} → 总繁忙度 = Render/3D 的 busy。
	var engines map[string]struct {
		Busy float64 `json:"busy"`
	}
	if raw, ok := sample["engines"]; ok {
		_ = json.Unmarshal(raw, &engines)
	}
	renderBusy := 0.0
	found := false
	for name, e := range engines {
		if strings.HasPrefix(name, "Render/3D") || strings.HasPrefix(name, "Render") {
			renderBusy += e.Busy
			found = true
		}
	}
	info := GPUInfo{
		Index:  0,
		Vendor: vendorIntel,
		Name:   "Intel GPU",
		Driver: "",
	}
	if found {
		info.Utilization = &renderBusy
	}
	// name / driver 可从 sample["devname"] 或 sample["period"]["duration"] 之类的元数据里
	// 挖出,但 intel_gpu_top 未稳定暴露 → 保守用占位。
	if raw, ok := sample["devname"]; ok {
		var dn string
		if json.Unmarshal(raw, &dn) == nil && strings.TrimSpace(dn) != "" {
			info.Name = dn
		}
	}
	b.gpus = append(b.gpus, info)

	// Clients:{"<pid>/<name>": {"Render/3D": 1.2, "Blitter": 0.0, ...}}
	if raw, ok := sample["clients"]; ok {
		var clients map[string]map[string]float64
		if json.Unmarshal(raw, &clients) == nil {
			b.procs = parseIntelClients(clients, &b)
		}
	}
	return b, nil
}

// parseIntelClients 把 intel_gpu_top 的 clients 键位 "PID/name" → ProcessInfo;
// GPUIndices 留空(intel_gpu_top 未给索引)。
func parseIntelClients(clients map[string]map[string]float64, b *vendorBundle) []ProcessInfo {
	keys := make([]string, 0, len(clients))
	for k := range clients {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]ProcessInfo, 0, len(keys))
	for _, k := range keys {
		pidStr, name, _ := strings.Cut(k, "/")
		pid, err := strconv.Atoi(strings.TrimSpace(pidStr))
		if err != nil {
			continue
		}
		out = append(out, ProcessInfo{
			PID:        pid,
			Name:       strings.TrimSpace(name),
			Vendor:     vendorIntel,
			GPUIndices: []int{},
			Note:       "Intel intel_gpu_top clients 只给引擎繁忙度,未给显存与 GPU 索引",
		})
	}
	return out
}

// --- 合并 + 全局索引重排 ---

// mergeBundles 把多厂商 bundle 合并为全局列表:按 NVIDIA→AMD→Intel 顺序
// 铺开 Index,并把 ProcessInfo.GPUIndices 的厂商内序号重映射到全局序号。
// skipped 厂商的 note 一并汇入最终 note。
func mergeBundles(bundles []vendorBundle) (gpus []GPUInfo, procs []ProcessInfo, note string, fatal error) {
	// 厂商顺序与 bundle 顺序一致(由 collect 保证);先建立厂商→起始偏移。
	offset := map[string]int{}
	next := 0
	for _, b := range bundles {
		if b.fatal != nil {
			return nil, nil, "", b.fatal
		}
		offset[b.vendor] = next
		next += len(b.gpus)
	}
	for _, b := range bundles {
		if b.note != "" {
			note = mergeNotes(note, b.note)
		}
		for _, g := range b.gpus {
			// 稠密假设:offset 按厂商 GPU 条数累加(非 maxIndex+1)。NVIDIA
			// nvidia-smi 的 index 列若稀疏(如 0/3 并存),厂商内序号保留
			// 自身值仅整体平移,跨厂商不保证全局唯一(真机未验证)。
			g.Index += offset[b.vendor]
			gpus = append(gpus, g)
		}
		for _, p := range b.procs {
			np := p
			if len(p.GPUIndices) > 0 {
				remapped := make([]int, 0, len(p.GPUIndices))
				for _, vi := range p.GPUIndices {
					remapped = append(remapped, vi+offset[b.vendor])
				}
				sort.Ints(remapped)
				np.GPUIndices = remapped
			}
			procs = append(procs, np)
		}
	}
	return gpus, procs, note, nil
}

// --- 公开工具入口 ---

// List 返回 gpu_list 结果(仅身份字段);全缺时 gpus=[] + note 声明可选依赖缺失。
func (s *service) List(ctx context.Context) (GPUListResult, error) {
	bundles, err := s.collect(ctx)
	if err != nil {
		return GPUListResult{}, err
	}
	gpus, _, note, fatal := mergeBundles(bundles)
	if fatal != nil {
		return GPUListResult{}, fatal
	}
	out := make([]GPUInfo, 0, len(gpus))
	for _, g := range gpus {
		// gpu_list 只回身份字段;测量字段在 gpu_status。
		out = append(out, GPUInfo{Index: g.Index, Vendor: g.Vendor, Name: g.Name, Driver: g.Driver})
	}
	if len(out) == 0 {
		note = mergeNotes(note, "未探测到任何 GPU(可选依赖全缺失或无 GPU)")
	}
	return GPUListResult{GPUs: out, Note: note}, nil
}

// StatusArgs / ProcessesArgs / MemoryArgs 是 gpu_status/gpu_processes/gpu_memory
// 的可选 GPU 索引参数。
type gpuSelectArgs struct {
	GPU *int
}

// Validate 校验 gpu 索引边界;nil 表示"全部"。
func (a gpuSelectArgs) Validate() error {
	if a.GPU == nil {
		return nil
	}
	if *a.GPU < 0 {
		return fmt.Errorf("gpu 索引必须 ≥ 0: %d", *a.GPU)
	}
	return nil
}

// Status 返回 gpu_status 结果(gpus 含全部测量字段)。
// gpu 非 nil 时按 Index 过滤并校验存在;越界报错。
func (s *service) Status(ctx context.Context, a gpuSelectArgs) (GPUStatusResult, error) {
	if err := a.Validate(); err != nil {
		return GPUStatusResult{}, err
	}
	bundles, err := s.collect(ctx)
	if err != nil {
		return GPUStatusResult{}, err
	}
	gpus, _, note, fatal := mergeBundles(bundles)
	if fatal != nil {
		return GPUStatusResult{}, fatal
	}
	if a.GPU != nil {
		found := false
		filtered := gpus[:0:0]
		for _, g := range gpus {
			if g.Index == *a.GPU {
				filtered = append(filtered, g)
				found = true
			}
		}
		if !found {
			return GPUStatusResult{}, fmt.Errorf("gpu 索引不存在: %d(共 %d 张 GPU)", *a.GPU, len(gpus))
		}
		gpus = filtered
	}
	// 空集合显式 [] 而非 nil,保证 wire 形态 "gpus":[] 与 gpu_list / gpu_processes
	// / gpu_memory 一致(LLM 客户端可统一按数组迭代)。
	if len(gpus) == 0 {
		gpus = []GPUInfo{}
		note = mergeNotes(note, "未探测到任何 GPU(可选依赖全缺失或无 GPU)")
	}
	return GPUStatusResult{GPUs: gpus, Note: note}, nil
}

// Processes 返回 gpu_processes 结果;gpu 非 nil 时只保留能映射到该 GPU 的
// 进程(AMD/Intel 因 GPUIndices 为空 → 保守过滤掉,note 写明数量与原因,
// 避免误以为"系统无 AMD/Intel 进程")。
func (s *service) Processes(ctx context.Context, a gpuSelectArgs) (GPUProcessesResult, error) {
	if err := a.Validate(); err != nil {
		return GPUProcessesResult{}, err
	}
	bundles, err := s.collect(ctx)
	if err != nil {
		return GPUProcessesResult{}, err
	}
	gpus, procs, note, fatal := mergeBundles(bundles)
	if fatal != nil {
		return GPUProcessesResult{}, fatal
	}
	if a.GPU != nil {
		if !containsIndex(gpus, *a.GPU) {
			return GPUProcessesResult{}, fmt.Errorf("gpu 索引不存在: %d(共 %d 张 GPU)", *a.GPU, len(gpus))
		}
		filtered := procs[:0:0]
		// droppedUnmapped 统计 GPUIndices 为空的进程(AMD/Intel):无法判定是否占用
		// *a.GPU,保守过滤,note 写明被过滤数量供 LLM 客户端理解"无 AMD/Intel 进程"
		// 与"被过滤掉"是两种语义。
		droppedUnmapped := 0
		for _, p := range procs {
			if len(p.GPUIndices) == 0 {
				droppedUnmapped++
				continue
			}
			for _, gi := range p.GPUIndices {
				if gi == *a.GPU {
					filtered = append(filtered, p)
					break
				}
			}
		}
		procs = filtered
		if droppedUnmapped > 0 {
			note = mergeNotes(note, fmt.Sprintf(
				"指定 gpu=%d 时,AMD/Intel 等 %d 个进程未提供 GPU 索引,无法按索引匹配,已从结果中排除", *a.GPU, droppedUnmapped))
		}
	}
	if procs == nil {
		procs = []ProcessInfo{}
	}
	return GPUProcessesResult{Processes: procs, Note: note}, nil
}

// Memory 返回 gpu_memory 结果:每设备的 total/used/free + 可映射到该 GPU 的进程。
func (s *service) Memory(ctx context.Context, a gpuSelectArgs) (GPUMemoryResult, error) {
	if err := a.Validate(); err != nil {
		return GPUMemoryResult{}, err
	}
	bundles, err := s.collect(ctx)
	if err != nil {
		return GPUMemoryResult{}, err
	}
	gpus, procs, note, fatal := mergeBundles(bundles)
	if fatal != nil {
		return GPUMemoryResult{}, fatal
	}
	if a.GPU != nil {
		if !containsIndex(gpus, *a.GPU) {
			return GPUMemoryResult{}, fmt.Errorf("gpu 索引不存在: %d(共 %d 张 GPU)", *a.GPU, len(gpus))
		}
	}
	devices := make([]MemoryBlock, 0, len(gpus))
	for _, g := range gpus {
		if a.GPU != nil && g.Index != *a.GPU {
			continue
		}
		blk := MemoryBlock{
			Index:     g.Index,
			Vendor:    g.Vendor,
			Processes: []ProcessInfo{},
		}
		if g.MemoryTotal != nil {
			blk.HasMemory = true
			blk.TotalMiB = *g.MemoryTotal
			if g.MemoryUsed != nil {
				blk.UsedMiB = *g.MemoryUsed
			}
			if g.MemoryFree != nil {
				blk.FreeMiB = *g.MemoryFree
			} else {
				blk.FreeMiB = blk.TotalMiB - blk.UsedMiB
				if blk.FreeMiB < 0 {
					blk.FreeMiB = 0
				}
			}
		}
		for _, p := range procs {
			for _, gi := range p.GPUIndices {
				if gi == g.Index {
					blk.Processes = append(blk.Processes, p)
					break
				}
			}
		}
		devices = append(devices, blk)
	}
	if devices == nil {
		devices = []MemoryBlock{}
	}
	if len(devices) == 0 {
		note = mergeNotes(note, "未探测到任何 GPU(可选依赖全缺失或无 GPU)")
	}
	return GPUMemoryResult{Devices: devices, Note: note}, nil
}

// containsIndex 判定 gpus 中是否包含指定 Index。
func containsIndex(gpus []GPUInfo, idx int) bool {
	for _, g := range gpus {
		if g.Index == idx {
			return true
		}
	}
	return false
}
