// gpu_test 覆盖三厂商解析、可选依赖探测、退出码降级、stderr 回归、index 校验、
// 全局索引重排与进程重映射。fixture 全部在 testdata/,真机未验证(nvidia-smi
// / intel_gpu_top 未预装,rocm-smi 装了但无 AMD GPU);夹具来源:
//
//   - nvidia_query_2gpu.txt / nvidia_compute_apps_2gpu.txt:NVIDIA 文档稳定键位
//     (nvidia-smi 主手册),开发机无真机验证。
//   - amd_query_1gpu.json / amd_showpids_1gpu.json:rocm-smi 1.4.x 的 printLog /
//     print2DArray 源码常量字面量。
//   - intel_top_1sample.json:intel-gpu-tools 的 JSON writer 上游字段嵌套。
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
)

const fixtureDir = "testdata"

// loadFixture 读夹具字节(测试在包目录内执行)。
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(fixtureDir + "/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// splitLines 把多行夹具切成逐行(去掉末尾空行)。
func splitLines(b []byte) [][]byte {
	out := bytes.Split(b, []byte{'\n'})
	if len(out) > 0 && len(out[len(out)-1]) == 0 {
		out = out[:len(out)-1]
	}
	return out
}

// fakeRunner 按 results 顺序分配每次 vendor CLI 调用的 stdout/err;记录最后一次
// 调用的 bin/args,便于断言厂商选择与 command line。
type fakeRunner struct {
	calls   int
	results []fakeResult
	lastBin string
	lastArg []string
}

// fakeResult 是单次调用的脚本:lines 逐行喂 onLine;err 在喂完后返回
// (execError / fs.PathError);希望 onLine 返回 false 即中止时用 abortOnLine。
type fakeResult struct {
	lines       [][]byte
	err         error
	abortOnLine bool
}

func (f *fakeRunner) run(_ context.Context, bin string, _ io.Reader, onLine func([]byte) bool, args ...string) error {
	f.lastBin = bin
	f.lastArg = append([]string(nil), args...)
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

// alwaysProbe 测试默认探针:所有预设 binary 都"在"。
func alwaysProbe(string) bool { return true }

// newFakeService 装配挂 fakeRunner 的 service(all probe=true)。
func newFakeService(results ...fakeResult) (*service, *fakeRunner) {
	fr := &fakeRunner{results: results}
	return &service{run: fr.run, probe: alwaysProbe, timeout: gpuTimeout}, fr
}

// fi 是 float64 指针构造的便捷别名。
func fi(v float64) *float64 { return &v }

// ptrEqual 比较 *float64 是否等值(nil==nil)。
func ptrEqual(a, b *float64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// ptrStr 是 *float64 的稳定字符串表示(测试报错信息用)。
func ptrStr(p *float64) string {
	if p == nil {
		return "nil"
	}
	return strconv.FormatFloat(*p, 'f', -1, 64)
}

// --- 解析层 ---

// TestParseNvidiaFloat 覆盖 N/A / Not Supported / 单位后缀 / 非法值。
func TestParseNvidiaFloat(t *testing.T) {
	cases := []struct {
		in   string
		want *float64
	}{
		{"42", fi(42)},
		{"75.5", fi(75.5)},
		{"[N/A]", nil},
		{"[Not Supported]", nil},
		{"[Insufficient Permissions]", nil},
		{"65.32 W", fi(65.32)},
		{"8 MiB", fi(8)},
		{"50%", fi(50)},
		{"", nil},
		{"abc", nil},
	}
	for _, c := range cases {
		if got := parseNvidiaFloat(c.in); !ptrEqual(got, c.want) {
			t.Errorf("parseNvidiaFloat(%q) = %s, want %s", c.in, ptrStr(got), ptrStr(c.want))
		}
	}
}

// TestParseAMDNumber 覆盖 N/A / Unsupported / 数值。
func TestParseAMDNumber(t *testing.T) {
	cases := []struct {
		in   string
		want *float64
	}{
		{"45.0", fi(45)},
		{"0", fi(0)},
		{"N/A", nil},
		{"Unsupported", nil},
		{"Not Supported", nil},
		{"", nil},
	}
	for _, c := range cases {
		if got := parseAMDNumber(c.in); !ptrEqual(got, c.want) {
			t.Errorf("parseAMDNumber(%q) = %s, want %s", c.in, ptrStr(got), ptrStr(c.want))
		}
	}
}

// TestParseNvidiaRow_NameWithComma 验证 encoding/csv 不被型号内逗号切断。
func TestParseNvidiaRow_NameWithComma(t *testing.T) {
	rec, err := parseNvidiaRow(`0, GPU-x, "NVIDIA A100, 80GB", 535.86.10, 45, 12, 24564, 0, 24564, 65`)
	if err != nil {
		t.Fatalf("parseNvidiaRow: %v", err)
	}
	if len(rec) != len(nvidiaQueryColumns) {
		t.Fatalf("列数 = %d, want %d", len(rec), len(nvidiaQueryColumns))
	}
	if rec[2] != "NVIDIA A100, 80GB" {
		t.Errorf("name = %q, want %q", rec[2], "NVIDIA A100, 80GB")
	}
}

// TestMergeNotes 去空白/去重/拼接。
func TestMergeNotes(t *testing.T) {
	got := mergeNotes("", "a", " a ", "b", "b")
	if got != "a; b" {
		t.Errorf("mergeNotes = %q, want %q", got, "a; b")
	}
}

// --- NVIDIA service 层 ---

// nvidiaFixtureResults 用两份夹具装配 nvidiaProbe 的两次调用。
func nvidiaFixtureResults(t *testing.T) []fakeResult {
	t.Helper()
	return []fakeResult{
		{lines: splitLines(loadFixture(t, "nvidia_query_2gpu.txt"))},
		{lines: splitLines(loadFixture(t, "nvidia_compute_apps_2gpu.txt"))},
	}
}

// TestNvidiaProbe_TwoGPUs 两卡 + 三进程解析,含 [N/A] 功率字段留空。
func TestNvidiaProbe_TwoGPUs(t *testing.T) {
	svc, fr := newFakeService(nvidiaFixtureResults(t)...)
	b, err := svc.nvidiaProbe(context.Background())
	if err != nil {
		t.Fatalf("nvidiaProbe: %v", err)
	}
	if len(b.gpus) != 2 {
		t.Fatalf("gpus = %d, want 2", len(b.gpus))
	}
	g0 := b.gpus[0]
	if g0.Vendor != vendorNVIDIA || g0.Name != "NVIDIA GeForce RTX 4090" || g0.Driver != "535.86.10" {
		t.Errorf("g0 身份字段 = %+v", g0)
	}
	if !ptrEqual(g0.Temperature, fi(45)) || !ptrEqual(g0.Utilization, fi(12)) ||
		!ptrEqual(g0.MemoryTotal, fi(24564)) || !ptrEqual(g0.MemoryUsed, fi(1234)) ||
		!ptrEqual(g0.MemoryFree, fi(23330)) || !ptrEqual(g0.Power, fi(65.32)) {
		t.Errorf("g0 测量字段 = %+v", g0)
	}
	if b.gpus[1].Power != nil {
		t.Errorf("g1.Power = %s, want nil([N/A])", ptrStr(b.gpus[1].Power))
	}
	if len(b.procs) != 3 {
		t.Fatalf("procs = %d, want 3", len(b.procs))
	}
	// 第一个进程映射到 GPU UUID aaaa → vendor-local index 0。
	if len(b.procs[0].GPUIndices) != 1 || b.procs[0].GPUIndices[0] != 0 {
		t.Errorf("procs[0].GPUIndices = %v, want [0]", b.procs[0].GPUIndices)
	}
	if !ptrEqual(b.procs[0].MemoryMiB, fi(1024)) {
		t.Errorf("procs[0].MemoryMiB = %s, want 1024", ptrStr(b.procs[0].MemoryMiB))
	}
	if fr.lastArg[0] != "--query-compute-apps=gpu_uuid,pid,process_name,used_memory" {
		t.Errorf("last args = %v", fr.lastArg)
	}
}

// --- AMD service 层 ---

// amdFixtureResults 用两份夹具装配 amdProbe 的两次调用。
func amdFixtureResults(t *testing.T) []fakeResult {
	t.Helper()
	return []fakeResult{
		{lines: splitLines(loadFixture(t, "amd_query_1gpu.json"))},
		{lines: splitLines(loadFixture(t, "amd_showpids_1gpu.json"))},
	}
}

// TestAMDProbe_OneGPU 一卡解析,含字节→MiB 换算、free 推导、温度优先级、进程空索引。
func TestAMDProbe_OneGPU(t *testing.T) {
	svc, _ := newFakeService(amdFixtureResults(t)...)
	b, err := svc.amdProbe(context.Background())
	if err != nil {
		t.Fatalf("amdProbe: %v", err)
	}
	if len(b.gpus) != 1 {
		t.Fatalf("gpus = %d, want 1", len(b.gpus))
	}
	g := b.gpus[0]
	if g.Vendor != vendorAMD {
		t.Errorf("vendor = %q", g.Vendor)
	}
	// Card series 优先。
	if g.Name != "Radeon RX 7900 XTX" {
		t.Errorf("name = %q", g.Name)
	}
	// Driver version 从 system 块下发到每卡。
	if g.Driver != "6.1.2" {
		t.Errorf("driver = %q", g.Driver)
	}
	// 温度取 Sensor edge(45)。
	if !ptrEqual(g.Temperature, fi(45)) {
		t.Errorf("temperature = %s, want 45", ptrStr(g.Temperature))
	}
	if !ptrEqual(g.Utilization, fi(12)) {
		t.Errorf("utilization = %s, want 12", ptrStr(g.Utilization))
	}
	if !ptrEqual(g.Power, fi(65)) {
		t.Errorf("power = %s, want 65", ptrStr(g.Power))
	}
	// 25753026560 B = 24560 MiB。
	if !ptrEqual(g.MemoryTotal, fi(24560)) {
		t.Errorf("memory_total = %s, want 24560", ptrStr(g.MemoryTotal))
	}
	// 1293848576 B = 1234 MiB。
	if !ptrEqual(g.MemoryUsed, fi(1234)) {
		t.Errorf("memory_used = %s, want 1234", ptrStr(g.MemoryUsed))
	}
	// free = total - used = 23326 MiB。
	if !ptrEqual(g.MemoryFree, fi(23326)) {
		t.Errorf("memory_free = %s, want 23326", ptrStr(g.MemoryFree))
	}
	// AMD 进程:2 条,PID 升序,GPUIndices 留空 + note。
	if len(b.procs) != 2 {
		t.Fatalf("procs = %d, want 2", len(b.procs))
	}
	if b.procs[0].PID != 4242 || b.procs[1].PID != 5000 {
		t.Errorf("PID 顺序 = %d, %d", b.procs[0].PID, b.procs[1].PID)
	}
	if len(b.procs[0].GPUIndices) != 0 {
		t.Errorf("AMD procs[0].GPUIndices = %v, want 空", b.procs[0].GPUIndices)
	}
	if !strings.Contains(b.procs[0].Note, "未给索引") {
		t.Errorf("AMD proc note = %q", b.procs[0].Note)
	}
	// 1073741824 B = 1024 MiB。
	if !ptrEqual(b.procs[0].MemoryMiB, fi(1024)) {
		t.Errorf("procs[0].MemoryMiB = %s, want 1024", ptrStr(b.procs[0].MemoryMiB))
	}
}

// --- Intel service 层 ---

// TestIntelProbe_OneSample 单样本解析:Render/3D busy=12.3,clients → 2 进程。
func TestIntelProbe_OneSample(t *testing.T) {
	line := bytes.TrimSpace(loadFixture(t, "intel_top_1sample.json"))
	svc, fr := newFakeService(fakeResult{lines: [][]byte{line}, abortOnLine: true})
	b, err := svc.intelProbe(context.Background())
	if err != nil {
		t.Fatalf("intelProbe: %v", err)
	}
	if len(b.gpus) != 1 {
		t.Fatalf("gpus = %d, want 1", len(b.gpus))
	}
	g := b.gpus[0]
	if g.Vendor != vendorIntel {
		t.Errorf("vendor = %q", g.Vendor)
	}
	if !ptrEqual(g.Utilization, fi(12.3)) {
		t.Errorf("utilization = %s, want 12.3", ptrStr(g.Utilization))
	}
	// Intel 未暴露的字段一律 nil。
	if g.Temperature != nil || g.MemoryTotal != nil || g.Power != nil {
		t.Errorf("Intel 未暴露字段应为 nil: %+v", g)
	}
	if len(b.procs) != 2 {
		t.Fatalf("procs = %d, want 2", len(b.procs))
	}
	if b.procs[0].PID != 4242 || b.procs[0].Name != "python" {
		t.Errorf("procs[0] = %+v", b.procs[0])
	}
	// -J -s 1000 参数与首样本即停。
	if len(fr.lastArg) != 3 || fr.lastArg[0] != "-J" || fr.lastArg[1] != "-s" || fr.lastArg[2] != "1000" {
		t.Errorf("intel args = %v", fr.lastArg)
	}
}

// --- 可选依赖探测 / 降级 ---

// TestCollect_AllVendorsMissing 三厂商 probe=false → skipped、全 note、无错误。
func TestCollect_AllVendorsMissing(t *testing.T) {
	fr := &fakeRunner{}
	svc := &service{run: fr.run, probe: func(string) bool { return false }, timeout: gpuTimeout}
	got, err := svc.Status(context.Background(), gpuSelectArgs{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(got.GPUs) != 0 {
		t.Errorf("gpus = %d, want 0", len(got.GPUs))
	}
	for _, want := range []string{"nvidia 不可用", "amd 不可用", "intel 不可用"} {
		if !strings.Contains(got.Note, want) {
			t.Errorf("note 缺 %q: %q", want, got.Note)
		}
	}
	if fr.calls != 0 {
		t.Errorf("全缺失时仍调用了 %d 次 CLI", fr.calls)
	}
}

// TestCollect_OnlyNvidiaPresent 仅 NVIDIA 可用:结果只含 NVIDIA,note 声明另两厂商缺失。
func TestCollect_OnlyNvidiaPresent(t *testing.T) {
	svc, _ := newFakeService(nvidiaFixtureResults(t)...)
	svc.probe = func(bin string) bool { return bin == nvidiaSmiBin }
	got, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got.GPUs) != 2 {
		t.Fatalf("gpus = %d, want 2", len(got.GPUs))
	}
	if got.GPUs[0].Vendor != vendorNVIDIA {
		t.Errorf("vendor = %q", got.GPUs[0].Vendor)
	}
	if !strings.Contains(got.Note, "amd 不可用") || !strings.Contains(got.Note, "intel 不可用") {
		t.Errorf("note = %q", got.Note)
	}
}

// TestList_DropsMeasurementFields gpu_list 只回身份字段,测量字段为 null。
func TestList_DropsMeasurementFields(t *testing.T) {
	svc, _ := newFakeService(nvidiaFixtureResults(t)...)
	svc.probe = func(bin string) bool { return bin == nvidiaSmiBin }
	got, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	g := got.GPUs[0]
	if g.Temperature != nil || g.Utilization != nil || g.MemoryTotal != nil || g.Power != nil {
		t.Errorf("gpu_list 应只回身份字段: %+v", g)
	}
}

// --- 退出码语义 / stderr 回归 ---

// TestHandleVendorError_NvidiaNoDevices rc=1 + "No devices were found" → 空集降级。
func TestHandleVendorError_NvidiaNoDevices(t *testing.T) {
	err := &execError{Code: 1, Stderr: "No devices were found", Cause: errors.New("exit 1")}
	note, fatal := handleVendorError(vendorNVIDIA, err)
	if fatal || !strings.Contains(note, "未发现") {
		t.Errorf("note=%q fatal=%v", note, fatal)
	}
}

// TestHandleVendorError_NvidiaRC2 rc=2(NVML 不可用)→ 致命。
func TestHandleVendorError_NvidiaRC2(t *testing.T) {
	err := &execError{Code: 2, Stderr: "NVIDIA-SMI has failed", Cause: errors.New("exit 2")}
	if _, fatal := handleVendorError(vendorNVIDIA, err); !fatal {
		t.Error("rc=2 应为致命")
	}
}

// TestHandleVendorError_AMDNoGPUs rc=1 + "No AMD GPUs" → 空集降级。
func TestHandleVendorError_AMDNoGPUs(t *testing.T) {
	err := &execError{Code: 1, Stderr: "WARNING: No AMD GPUs specified", Cause: errors.New("exit 1")}
	note, fatal := handleVendorError(vendorAMD, err)
	if fatal || !strings.Contains(note, "无 AMD GPU") {
		t.Errorf("note=%q fatal=%v", note, fatal)
	}
}

// TestHandleVendorError_AMDConcise rc=1 + concise 拒绝 → 空集降级(本机实测文案)。
func TestHandleVendorError_AMDConcise(t *testing.T) {
	err := &execError{Code: 1, Stderr: "ERROR: Cannot print JSON/CSV output for concise output", Cause: errors.New("exit 1")}
	if _, fatal := handleVendorError(vendorAMD, err); fatal {
		t.Error("concise 拒绝应降级非致命")
	}
}

// TestHandleVendorError_AMDUsage rc=2(argparse)→ 致命。
func TestHandleVendorError_AMDUsage(t *testing.T) {
	err := &execError{Code: 2, Stderr: "usage: rocm-smi", Cause: errors.New("exit 2")}
	if _, fatal := handleVendorError(vendorAMD, err); !fatal {
		t.Error("rc=2 应为致命")
	}
}

// TestHandleVendorError_MissingBinary ENOENT → 非致命(运行期 binary 被拔)。
func TestHandleVendorError_MissingBinary(t *testing.T) {
	note, fatal := handleVendorError(vendorNVIDIA, &fs.PathError{Op: "fork/exec", Path: "/usr/bin/nvidia-smi", Err: fs.ErrNotExist})
	if fatal || !strings.Contains(note, "不可用") {
		t.Errorf("note=%q fatal=%v", note, fatal)
	}
}

// TestStatus_StderrPropagatedToError 真故障时 stderr 内容必须进入错误信息
// (承接 Task 3 的 stderr 回归)。
func TestStatus_StderrPropagatedToError(t *testing.T) {
	svc, _ := newFakeService(fakeResult{
		lines: nil,
		err:   &execError{Code: 2, Stderr: "NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver", Cause: errors.New("exit 2")},
	})
	svc.probe = func(bin string) bool { return bin == nvidiaSmiBin }
	_, err := svc.Status(context.Background(), gpuSelectArgs{})
	if err == nil {
		t.Fatal("期望致命错误")
	}
	if !strings.Contains(err.Error(), "couldn't communicate") {
		t.Errorf("错误未带 stderr: %v", err)
	}
}

// TestCollect_NvidiaNoDevicesProducesEmptyList rc=1+"No devices" → 空集 + note,不报错。
func TestCollect_NvidiaNoDevicesProducesEmptyList(t *testing.T) {
	svc, _ := newFakeService(fakeResult{
		err: &execError{Code: 1, Stderr: "No devices were found", Cause: errors.New("exit 1")},
	})
	svc.probe = func(bin string) bool { return bin == nvidiaSmiBin }
	got, err := svc.Status(context.Background(), gpuSelectArgs{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(got.GPUs) != 0 {
		t.Errorf("gpus = %d, want 0", len(got.GPUs))
	}
	if !strings.Contains(got.Note, "未发现 NVIDIA 设备") {
		t.Errorf("note = %q", got.Note)
	}
}

// --- 全局索引重排 / 进程映射 ---

// TestMergeBundles_GlobalIndexRemap NVIDIA 2 卡 + AMD 1 卡 → 全局 Index 0,1,2;
// AMD 进程 GPUIndices 留空(未映射)。
func TestMergeBundles_GlobalIndexRemap(t *testing.T) {
	bundles := []vendorBundle{
		{vendor: vendorNVIDIA, gpus: []GPUInfo{
			{Index: 0, Vendor: vendorNVIDIA, Name: "n0"},
			{Index: 1, Vendor: vendorNVIDIA, Name: "n1"},
		}, procs: []ProcessInfo{
			{PID: 100, Name: "p100", Vendor: vendorNVIDIA, GPUIndices: []int{1}},
		}},
		{vendor: vendorAMD, gpus: []GPUInfo{
			{Index: 0, Vendor: vendorAMD, Name: "a0"},
		}, procs: []ProcessInfo{
			{PID: 200, Name: "p200", Vendor: vendorAMD, GPUIndices: []int{}},
		}},
	}
	gpus, procs, _, err := mergeBundles(bundles)
	if err != nil {
		t.Fatalf("mergeBundles: %v", err)
	}
	if len(gpus) != 3 {
		t.Fatalf("gpus = %d, want 3", len(gpus))
	}
	if gpus[0].Index != 0 || gpus[1].Index != 1 || gpus[2].Index != 2 {
		t.Errorf("全局 Index = %d,%d,%d, want 0,1,2", gpus[0].Index, gpus[1].Index, gpus[2].Index)
	}
	if gpus[2].Vendor != vendorAMD {
		t.Errorf("gpus[2].Vendor = %q", gpus[2].Vendor)
	}
	// NVIDIA 进程 GPUIndices 1 → 全局 1(偏移 0);AMD 进程留空。
	if len(procs[0].GPUIndices) != 1 || procs[0].GPUIndices[0] != 1 {
		t.Errorf("nvidia proc GPUIndices = %v, want [1]", procs[0].GPUIndices)
	}
	if len(procs[1].GPUIndices) != 0 {
		t.Errorf("amd proc GPUIndices = %v, want 空", procs[1].GPUIndices)
	}
}

// --- index 校验 ---

// TestSelectArgs_Validate 负数被拒,nil/0 通过。
func TestSelectArgs_Validate(t *testing.T) {
	if err := (gpuSelectArgs{GPU: nil}).Validate(); err != nil {
		t.Errorf("nil 校验失败: %v", err)
	}
	zero := 0
	if err := (gpuSelectArgs{GPU: &zero}).Validate(); err != nil {
		t.Errorf("0 校验失败: %v", err)
	}
	neg := -1
	if err := (gpuSelectArgs{GPU: &neg}).Validate(); err == nil {
		t.Error("负数应被拒")
	}
}

// ii 是 *int 便捷构造,测试边界用例。
func ii(v int) *int { return &v }

// TestStatus_OutOfRange 越界报错。
func TestStatus_OutOfRange(t *testing.T) {
	svc, _ := newFakeService(nvidiaFixtureResults(t)...)
	svc.probe = func(bin string) bool { return bin == nvidiaSmiBin }
	_, err := svc.Status(context.Background(), gpuSelectArgs{GPU: ii(99)})
	if err == nil || !strings.Contains(err.Error(), "索引不存在") {
		t.Errorf("err = %v, want 索引不存在", err)
	}
}

// TestProcesses_OutOfRange 越界报错。
func TestProcesses_OutOfRange(t *testing.T) {
	svc, _ := newFakeService(nvidiaFixtureResults(t)...)
	svc.probe = func(bin string) bool { return bin == nvidiaSmiBin }
	_, err := svc.Processes(context.Background(), gpuSelectArgs{GPU: ii(99)})
	if err == nil || !strings.Contains(err.Error(), "索引不存在") {
		t.Errorf("err = %v, want 索引不存在", err)
	}
}

// --- 工具层输出形态 ---

// TestStatus_FilterByIndex 指定 index 后只回该卡,Index 字段保持全局口径。
func TestStatus_FilterByIndex(t *testing.T) {
	svc, _ := newFakeService(nvidiaFixtureResults(t)...)
	svc.probe = func(bin string) bool { return bin == nvidiaSmiBin }
	got, err := svc.Status(context.Background(), gpuSelectArgs{GPU: ii(1)})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(got.GPUs) != 1 || got.GPUs[0].Index != 1 {
		t.Errorf("gpus = %+v, want 单卡 Index=1", got.GPUs)
	}
}

// TestProcesses_FilterDropsAMD 指定 AMD index 时,AMD 进程因 GPUIndices 空被过滤。
func TestProcesses_FilterDropsAMD(t *testing.T) {
	svc, _ := newFakeService(amdFixtureResults(t)...)
	svc.probe = func(bin string) bool { return bin == rocmSmiBin }
	got, err := svc.Processes(context.Background(), gpuSelectArgs{GPU: ii(0)})
	if err != nil {
		t.Fatalf("Processes: %v", err)
	}
	if len(got.Processes) != 0 {
		t.Errorf("AMD 进程应被过滤,got %v", got.Processes)
	}
}

// TestMemory_EmptyIsArrayNotNil 全缺失时 devices 必须显式 []。
func TestMemory_EmptyIsArrayNotNil(t *testing.T) {
	svc := &service{run: (&fakeRunner{}).run, probe: func(string) bool { return false }, timeout: gpuTimeout}
	got, err := svc.Memory(context.Background(), gpuSelectArgs{})
	if err != nil {
		t.Fatalf("Memory: %v", err)
	}
	if got.Devices == nil {
		t.Error("Devices 为 nil,应为 []")
	}
	if got.Note == "" {
		t.Error("全缺失应有 note")
	}
}

// TestProcesses_EmptyIsArrayNotNil 无进程时 processes 显式 []。
func TestProcesses_EmptyIsArrayNotNil(t *testing.T) {
	svc, _ := newFakeService(fakeResult{lines: nil})
	svc.probe = func(bin string) bool { return bin == nvidiaSmiBin }
	got, err := svc.Processes(context.Background(), gpuSelectArgs{})
	if err != nil {
		t.Fatalf("Processes: %v", err)
	}
	if got.Processes == nil {
		t.Error("Processes 为 nil,应为 []")
	}
}

// TestMemory_MiBAndProcesses gpu_memory 汇总 total/used/free + NVIDIA 进程映射。
func TestMemory_MiBAndProcesses(t *testing.T) {
	svc, _ := newFakeService(nvidiaFixtureResults(t)...)
	svc.probe = func(bin string) bool { return bin == nvidiaSmiBin }
	got, err := svc.Memory(context.Background(), gpuSelectArgs{})
	if err != nil {
		t.Fatalf("Memory: %v", err)
	}
	if len(got.Devices) != 2 {
		t.Fatalf("devices = %d, want 2", len(got.Devices))
	}
	d0 := got.Devices[0]
	if !d0.HasMemory || d0.TotalMiB != 24564 || d0.UsedMiB != 1234 || d0.FreeMiB != 23330 {
		t.Errorf("device0 = %+v", d0)
	}
	// GPU0 有 2 个进程(aaaa: python + Xorg)。
	if len(d0.Processes) != 2 {
		t.Errorf("device0 进程数 = %d, want 2", len(d0.Processes))
	}
	// GPU1 只有 1 个进程(cccc: ollama)。
	if len(got.Devices[1].Processes) != 1 {
		t.Errorf("device1 进程数 = %d, want 1", len(got.Devices[1].Processes))
	}
}
