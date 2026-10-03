// integrity 只读解析与外部 CLI 编排的单测:fixture 驱动的 rpm -V 输出解析、
// 参数校验、分页/截断、缺失降级、退出码语义与真 exec 贯通。
//
// 数据源固定指向包内 testdata/ 的 rpm -V 输出夹具;外部 CLI 一律经 execRunner
// 注入替身或临时假脚本,测试零触碰宿主 rpm 数据库。唯一例外是
// TestRunRPM_RealStderr 系列走真 fork 验证 stderr/退出码管道(仍不读真实
// /var/lib/rpm)。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fixtureDir 是 testdata/ 的相对路径,测试在包目录内执行。
const fixtureDir = "testdata"

// fixturePath 返回夹具的绝对路径(真 exec 段假脚本需要绝对路径)。
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("解析夹具绝对路径失败: %v", err)
	}
	return abs
}

// loadLines 读 testdata 下 .txt 夹具并按行拆分(去空行),模拟 rpm -V 一行
// 一条差异的 stdout 形态。
func loadLines(t *testing.T, name string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("读夹具 %s 失败: %v", name, err)
	}
	var out [][]byte
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, []byte(line))
	}
	return out
}

// fakeRunner 是 execRunner 夹具:把 lines 逐行喂给 onLine;onLine 返回 false
// 时记录 aborted 并原地返回(模拟提前 kill 收工)。err 非 nil 时在 lines 喂
// 完后返回(可能是 execError / fs.PathError,用于模拟退出码与缺失二进制)。
type fakeRunner struct {
	lines   [][]byte
	err     error
	aborted bool
	args    []string
}

func (f *fakeRunner) run(_ context.Context, onLine func([]byte) bool, args ...string) error {
	f.args = append([]string(nil), args...)
	for _, line := range f.lines {
		if !onLine(line) {
			f.aborted = true
			return nil
		}
	}
	if f.err != nil {
		return f.err
	}
	return nil
}

// newFakeService 装配一个挂 fakeRunner 的 service(占位 runner = newService())。
func newFakeService(lines ...[]byte) (*service, *fakeRunner) {
	fr := &fakeRunner{lines: lines}
	return &service{run: fr.run, rpmTimeout: rpmTimeout}, fr
}

// --- 解析层 ---

// TestParseVerifyLine_Standard 9 字节 flag 矩阵 + 类型标记 + 路径的标准差异行。
func TestParseVerifyLine_Standard(t *testing.T) {
	got, ok := parseVerifyLine(`S.5....T.  c /etc/foo`)
	if !ok {
		t.Fatal("parseVerifyLine 标准行失败")
	}
	if got.Path != "/etc/foo" {
		t.Errorf("Path=%q, want /etc/foo", got.Path)
	}
	if got.Type != "c" {
		t.Errorf("Type=%q, want c(config)", got.Type)
	}
	if !got.Flags.Size || !got.Flags.MD5 || !got.Flags.Mtime {
		t.Errorf("S/5/T 应为 true: %+v", got.Flags)
	}
	if got.Flags.Mode || got.Flags.User || got.Flags.Group {
		t.Errorf("M/U/G 应为 false: %+v", got.Flags)
	}
}

// TestParseVerifyLine_Missing 缺失文件行(missing + 路径 + 括号备注)。
func TestParseVerifyLine_Missing(t *testing.T) {
	got, ok := parseVerifyLine(`missing     /usr/libexec/missing-file (Permission denied)`)
	if !ok {
		t.Fatal("parseVerifyLine missing 行失败")
	}
	if got.Path != "/usr/libexec/missing-file" {
		t.Errorf("Path=%q, want /usr/libexec/missing-file", got.Path)
	}
	if !got.Flags.Missing {
		t.Errorf("Missing 应为 true: %+v", got.Flags)
	}
}

// TestParseVerifyLine_Unreadable '?` 占位表示 rpm 无法读取该属性值(通常因权限),
// 但不等同于该属性差异;需要显式标记。
func TestParseVerifyLine_Unreadable(t *testing.T) {
	got, ok := parseVerifyLine(`..?......  c /etc/libaudit.conf`)
	if !ok {
		t.Fatal("parseVerifyLine '?` 行失败")
	}
	if !got.Flags.Unreadable {
		t.Errorf("Unreadable 应为 true: %+v", got.Flags)
	}
	if got.Flags.MD5 {
		t.Errorf("位 3 是 '?' 不是 '5',MD5 不应置 true: %+v", got.Flags)
	}
}

// TestParseVerifyLine_AllFlags 末位 T/C(mtime + capability)与无类型标记的组合。
func TestParseVerifyLine_AllFlags(t *testing.T) {
	got, ok := parseVerifyLine(`.......TC   /usr/bin/bar`)
	if !ok {
		t.Fatal("parseVerifyLine TC 行失败")
	}
	if got.Path != "/usr/bin/bar" || got.Type != "" {
		t.Errorf("Path=%q Type=%q, want /usr/bin/bar 与空 Type", got.Path, got.Type)
	}
	if !got.Flags.Mtime || !got.Flags.Caps {
		t.Errorf("T/P 应为 true: %+v", got.Flags)
	}
}

// TestParseVerifyLine_PCapability 单 P(capability 差异)+ 无类型标记。
func TestParseVerifyLine_PCapability(t *testing.T) {
	got, ok := parseVerifyLine(`P.........    /usr/bin/newuidmap`)
	if !ok {
		t.Fatal("parseVerifyLine P 行失败")
	}
	if !got.Flags.Caps {
		t.Errorf("Caps 应为 true: %+v", got.Flags)
	}
}

// TestParseVerifyLine_LinkOwner Group 与 Mode 组合。
func TestParseVerifyLine_LinkOwner(t *testing.T) {
	got, ok := parseVerifyLine(`....L....    /usr/lib64/libssl.so`)
	if !ok {
		t.Fatal("parseVerifyLine L 行失败")
	}
	if !got.Flags.Symlink {
		t.Errorf("Symlink 应为 true: %+v", got.Flags)
	}
	got, ok = parseVerifyLine(`..U......    /usr/bin/ls`)
	if !ok {
		t.Fatal("parseVerifyLine U 行失败")
	}
	if !got.Flags.User {
		t.Errorf("User 应为 true: %+v", got.Flags)
	}
	got, ok = parseVerifyLine(`......G..    /var/lib/rpm/rpmdb.sqlite`)
	if !ok {
		t.Fatal("parseVerifyLine G 行失败")
	}
	if !got.Flags.Group {
		t.Errorf("Group 应为 true: %+v", got.Flags)
	}
	got, ok = parseVerifyLine(`.M.......    /usr/bin/su`)
	if !ok {
		t.Fatal("parseVerifyLine M 行失败")
	}
	if !got.Flags.Mode {
		t.Errorf("Mode 应为 true: %+v", got.Flags)
	}
	got, ok = parseVerifyLine(`....D....    /dev/null`)
	if !ok {
		t.Fatal("parseVerifyLine D 行失败")
	}
	if !got.Flags.Device {
		t.Errorf("Device 应为 true: %+v", got.Flags)
	}
}

// TestParseVerifyLine_Skipped 空行、垃圾行、行长度不足一律跳过。
func TestParseVerifyLine_Skipped(t *testing.T) {
	for _, line := range []string{
		"",
		"   ",
		"hello",
		"S.5....T.",
		"missing",
	} {
		if _, ok := parseVerifyLine(line); ok {
			t.Errorf("行 %q 应跳过", line)
		}
	}
}

// TestParseVerifyOutput_MixedFixture 全量夹具:11 行混合差异,坏行跳过,整体不崩。
func TestParseVerifyOutput_MixedFixture(t *testing.T) {
	entries, skipped := parseVerifyOutput(loadLines(t, "rpm-verify-all.txt"))
	if len(entries) != 11 || skipped != 0 {
		t.Errorf("entries=%d skipped=%d, want 11/0", len(entries), skipped)
	}
	// 钉住首条(S/5/T)与末条(P)的关键位
	if !entries[0].Flags.Size || !entries[0].Flags.MD5 || !entries[0].Flags.Mtime {
		t.Errorf("首条 flags 错: %+v", entries[0])
	}
	if !entries[10].Flags.Caps {
		t.Errorf("末条 Caps 应为 true: %+v", entries[10])
	}
	// missing 行必须置 Missing
	if !entries[2].Flags.Missing {
		t.Errorf("missing 行 Missing 应为 true: %+v", entries[2])
	}
}

// --- 参数校验 ---

// TestVerifyArgsValidation 参数形状校验:package 注入/遍历、all 与 package 互斥、
// limit/offset 边界全部在拼 argv 之前拒绝。
func TestVerifyArgsValidation(t *testing.T) {
	cases := []struct {
		name string
		args VerifyArgs
		want string
	}{
		{"empty", VerifyArgs{}, "必须指定 package 或 all"},
		{"both", VerifyArgs{Package: ptrStr("bash"), All: true}, "package 与 all 不能同时"},
		{"package-injection", VerifyArgs{Package: ptrStr("bash; rm -rf /")}, "非法 package"},
		{"package-leading-dash", VerifyArgs{Package: ptrStr("--all")}, "非法 package"},
		{"package-traversal", VerifyArgs{Package: ptrStr("..")}, "非法 package"},
		{"package-empty", VerifyArgs{Package: ptrStr(""), All: true}, "非法 package"},
		{"limit-zero", VerifyArgs{All: true, Limit: ptrInt(0)}, "limit"},
		{"limit-huge", VerifyArgs{All: true, Limit: ptrInt(200000)}, "limit"},
		{"offset-negative", VerifyArgs{All: true, Offset: ptrInt(-1)}, "offset"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.args.Validate()
			if err == nil {
				t.Fatalf("应拒绝: %+v", c.args)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误 %q 应含 %q", err.Error(), c.want)
			}
		})
	}
}

// TestVerifyArgsDefaults 缺省值补齐:limit 默认 verifyDefaultLimit,offset 默认 0。
func TestVerifyArgsDefaults(t *testing.T) {
	a := VerifyArgs{All: true}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if a.Limit == nil || *a.Limit != verifyDefaultLimit {
		t.Errorf("缺省 limit 应为 %d, got %v", verifyDefaultLimit, a.Limit)
	}
	if a.Offset == nil || *a.Offset != 0 {
		t.Errorf("缺省 offset 应为 0, got %v", a.Offset)
	}
}

// TestUnchangedArgsValidation package 注入拒绝(unchanged 单包形态)。
func TestUnchangedArgsValidation(t *testing.T) {
	cases := []struct {
		name string
		args UnchangedArgs
		want string
	}{
		{"package-injection", UnchangedArgs{Package: ptrStr("bash && rm")}, "非法 package"},
		{"package-leading-dash", UnchangedArgs{Package: ptrStr("--nodeps")}, "非法 package"},
		{"limit-zero", UnchangedArgs{Limit: ptrInt(0)}, "limit"},
		{"offset-negative", UnchangedArgs{Offset: ptrInt(-5)}, "offset"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.args.Validate()
			if err == nil {
				t.Fatalf("应拒绝: %+v", c.args)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误 %q 应含 %q", err.Error(), c.want)
			}
		})
	}
}

// --- rpm_verify 单包形态 ---

// TestVerifySinglePackage_ParsesDiffs rc=1 时的差异解析:文档语义"rc=1 = 有差异",
// 必须 parse stdout 正常返回结果,而不是把 rc=1 当 fork 失败吞/上抛。
func TestVerifySinglePackage_ParsesDiffs(t *testing.T) {
	svc, fr := newFakeService(loadLines(t, "rpm-verify-package.txt")...)
	// 注入 rc=1 execError 模拟 rpm -V pkg 有差异时的退出码
	fr.err = &execError{Code: 1, Stderr: ""}
	res, err := svc.Verify(context.Background(), VerifyArgs{Package: ptrStr("bash")})
	if err != nil {
		t.Fatalf("rc=1(有差异)应正常返回结果: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Errorf("Entries=%d, want 2: %+v", len(res.Entries), res.Entries)
	}
	if res.Entries[0].Package != "bash" {
		t.Errorf("Package echo 错: %q", res.Entries[0].Package)
	}
	if !res.Entries[1].Flags.Missing {
		t.Errorf("missing 行 Missing 应为 true: %+v", res.Entries[1])
	}
}

// TestVerifySinglePackage_AllMatch rc=0 且 stdout 为空:全匹配,返回空集无 note。
func TestVerifySinglePackage_AllMatch(t *testing.T) {
	svc, _ := newFakeService()
	res, err := svc.Verify(context.Background(), VerifyArgs{Package: ptrStr("bash")})
	if err != nil {
		t.Fatalf("全匹配应成功: %v", err)
	}
	if len(res.Entries) != 0 {
		t.Errorf("全匹配应空集, got %+v", res.Entries)
	}
}

// TestVerifyAll_Pagination 超大输出分页:夹具供 2500 行、limit=1000,截断并返回
// total_lines=2500 / returned=1000 / truncated=true。
func TestVerifyAll_Pagination(t *testing.T) {
	lines := make([][]byte, 2500)
	for i := range lines {
		lines[i] = []byte("S.5....T.  c /etc/file" + strconv.Itoa(i))
	}
	svc, _ := newFakeService(lines...)
	limit := 1000
	res, err := svc.Verify(context.Background(), VerifyArgs{All: true, Limit: &limit})
	if err != nil {
		t.Fatalf("Verify 应成功: %v", err)
	}
	if res.TotalLines != 2500 {
		t.Errorf("TotalLines=%d, want 2500", res.TotalLines)
	}
	if res.Returned != 1000 {
		t.Errorf("Returned=%d, want 1000", res.Returned)
	}
	if !res.Truncated {
		t.Error("Truncated 应为 true")
	}
	if len(res.Entries) != 1000 {
		t.Errorf("Entries=%d, want 1000", len(res.Entries))
	}
	if res.Entries[0].Path != "/etc/file0" {
		t.Errorf("offset=0 应从首条开始, got %q", res.Entries[0].Path)
	}
}

// TestVerifyAll_Offset 偏移分页:offset=2000,limit=500 → 取第 2000..2499 条。
func TestVerifyAll_Offset(t *testing.T) {
	lines := make([][]byte, 2500)
	for i := range lines {
		lines[i] = []byte("S.5....T.  c /etc/file" + strconv.Itoa(i))
	}
	svc, _ := newFakeService(lines...)
	limit, offset := 500, 2000
	res, err := svc.Verify(context.Background(), VerifyArgs{All: true, Limit: &limit, Offset: &offset})
	if err != nil {
		t.Fatalf("Verify 应成功: %v", err)
	}
	if len(res.Entries) != 500 {
		t.Fatalf("Entries=%d, want 500", len(res.Entries))
	}
	if res.Entries[0].Path != "/etc/file2000" {
		t.Errorf("offset=2000 应从 /etc/file2000 开始, got %q", res.Entries[0].Path)
	}
	if res.Returned != 500 {
		t.Errorf("Returned=%d, want 500", res.Returned)
	}
	if res.TotalLines != 2500 {
		t.Errorf("TotalLines=%d, want 2500", res.TotalLines)
	}
}

// TestVerifyMissingBinaryInjected 注入 ENOENT 替身:降级为空集 + 显式 note。
func TestVerifyMissingBinaryInjected(t *testing.T) {
	svc := &service{
		rpmTimeout: rpmTimeout,
		run: func(_ context.Context, _ func([]byte) bool, _ ...string) error {
			return &fs.PathError{Op: "fork/exec", Path: rpmBinary, Err: fs.ErrNotExist}
		},
	}
	res, err := svc.Verify(context.Background(), VerifyArgs{Package: ptrStr("bash")})
	if err != nil {
		t.Fatalf("缺 binary 应降级而非报错: %v", err)
	}
	if len(res.Entries) != 0 || !strings.Contains(res.Note, "不可用") {
		t.Errorf("降级结果异常: %+v", res)
	}
}

// TestVerifyRealErrorPropagated rc≥2 真故障:必须 wrap 上抛,不吞。
func TestVerifyRealErrorPropagated(t *testing.T) {
	svc, fr := newFakeService()
	fr.err = &execError{Code: 2, Stderr: "cannot open Packages database"}
	_, err := svc.Verify(context.Background(), VerifyArgs{Package: ptrStr("bash")})
	if err == nil {
		t.Fatal("rc≥2 应上抛错误")
	}
	if !strings.Contains(err.Error(), "cannot open Packages database") {
		t.Errorf("错误应含 stderr: %q", err.Error())
	}
}

// TestVerifyPackageNotInstalled 单包形态下 rc=1 + "not installed" stderr = 包不存在,
// 以空集 + note 返回(不是 panic,也不当 fork 失败)。
func TestVerifyPackageNotInstalled(t *testing.T) {
	svc, fr := newFakeService()
	fr.err = &execError{Code: 1, Stderr: "package latex is not installed"}
	res, err := svc.Verify(context.Background(), VerifyArgs{Package: ptrStr("latex")})
	if err != nil {
		t.Fatalf("包不存在应降级而非报错: %v", err)
	}
	if len(res.Entries) != 0 || !strings.Contains(res.Note, "不存在") {
		t.Errorf("降级结果异常: %+v", res)
	}
}

// --- rpm_unchanged ---

// TestUnchanged_SinglePackage_Unchanged 单包 `rpm -V pkg` 空输出 → 包未被改动。
func TestUnchanged_SinglePackage_Unchanged(t *testing.T) {
	svc, _ := newFakeService()
	res, err := svc.Unchanged(context.Background(), UnchangedArgs{Package: ptrStr("bash")})
	if err != nil {
		t.Fatalf("Unchanged 应成功: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0] != "bash" {
		t.Errorf("Packages=%v, want [bash]", res.Packages)
	}
}

// TestUnchanged_SinglePackage_Changed 单包有差异 → 该包不在 unchanged 列表。
func TestUnchanged_SinglePackage_Changed(t *testing.T) {
	svc, fr := newFakeService(loadLines(t, "rpm-verify-package.txt")...)
	fr.err = &execError{Code: 1, Stderr: ""}
	res, err := svc.Unchanged(context.Background(), UnchangedArgs{Package: ptrStr("bash")})
	if err != nil {
		t.Fatalf("Unchanged 应成功: %v", err)
	}
	if len(res.Packages) != 0 {
		t.Errorf("Packages=%v, want []", res.Packages)
	}
	if res.TotalLines == 0 {
		t.Error("TotalLines 应统计差异行")
	}
}

// TestUnchanged_MissingBinaryInjected rpm 缺失 → 降级空集 + note,不 panic。
func TestUnchanged_MissingBinaryInjected(t *testing.T) {
	svc := &service{
		rpmTimeout: rpmTimeout,
		run: func(_ context.Context, _ func([]byte) bool, _ ...string) error {
			return &fs.PathError{Op: "fork/exec", Path: rpmBinary, Err: fs.ErrNotExist}
		},
	}
	res, err := svc.Unchanged(context.Background(), UnchangedArgs{})
	if err != nil {
		t.Fatalf("缺 binary 应降级而非报错: %v", err)
	}
	if len(res.Packages) != 0 || !strings.Contains(res.Note, "不可用") {
		t.Errorf("降级结果异常: %+v", res)
	}
}

// --- rpm_summary ---

// TestSummary_Counts 全量概览统计:changed_packages / changed_files /
// total_packages 三元组。
func TestSummary_Counts(t *testing.T) {
	// 通过串联 fake runner:第一次 rpm -Va 返回 11 行差异,后续 rpm -qf 每次
	// 返回 1 行归属包名。这里直接用单条 execError=1 让 Verify/Summary 走通。
	svc := &service{
		rpmTimeout: rpmTimeout,
		run:        summaryFakeRunner(),
	}
	res, err := svc.Summary(context.Background())
	if err != nil {
		t.Fatalf("Summary 应成功: %v", err)
	}
	if res.TotalPackages == 0 {
		t.Error("TotalPackages 应 > 0")
	}
	if res.ChangedFiles == 0 {
		t.Error("ChangedFiles 应 > 0")
	}
	if res.ChangedPackages == 0 {
		t.Error("ChangedPackages 应 > 0")
	}
}

// TestSummary_MissingBinaryInjected 缺 rpm 二进制 → 空 summary + note。
func TestSummary_MissingBinaryInjected(t *testing.T) {
	svc := &service{
		rpmTimeout: rpmTimeout,
		run: func(_ context.Context, _ func([]byte) bool, _ ...string) error {
			return &fs.PathError{Op: "fork/exec", Path: rpmBinary, Err: fs.ErrNotExist}
		},
	}
	res, err := svc.Summary(context.Background())
	if err != nil {
		t.Fatalf("缺 binary 应降级而非报错: %v", err)
	}
	if res.TotalPackages != 0 || !strings.Contains(res.Note, "不可用") {
		t.Errorf("降级结果异常: %+v", res)
	}
}

// --- execRunner / 真 exec ---

// TestRunRPM_RealStderrWrapped 真 fork 路径:rc=1 + stderr 必须进 execError.Stderr。
func TestRunRPM_RealStderrWrapped(t *testing.T) {
	writeFakeRPM(t, "#!/bin/sh\necho 'package latex is not installed' >&2\nexit 1\n")
	got := runRPM(context.Background(), func([]byte) bool { return true }, "-V", "latex")
	if got == nil {
		t.Fatal("rc=1 应返回 execError 而非 nil")
	}
	var ee *execError
	if !errors.As(got, &ee) {
		t.Fatalf("err 应为 *execError, got %T: %v", got, got)
	}
	if ee.Code != 1 {
		t.Errorf("Code=%d, want 1", ee.Code)
	}
	if !strings.Contains(ee.Stderr, "package latex is not installed") {
		t.Errorf("Stderr 应含 stderr 文本: %q", ee.Stderr)
	}
}

// TestRunRPM_RealRc2Stderr 真 fork 路径:rc=2 + stderr 必须 wrap。
func TestRunRPM_RealRc2Stderr(t *testing.T) {
	writeFakeRPM(t, "#!/bin/sh\necho 'cannot open Packages database' >&2\nexit 2\n")
	got := runRPM(context.Background(), func([]byte) bool { return true }, "-Va")
	if got == nil {
		t.Fatal("rc=2 应返回 execError")
	}
	var ee *execError
	if !errors.As(got, &ee) {
		t.Fatalf("err 应为 *execError, got %T", got)
	}
	if ee.Code != 2 {
		t.Errorf("Code=%d, want 2", ee.Code)
	}
}

// TestRunRPM_RealStdoutCaptured 真 fork 路径:rc=0 时 stdout 逐行回传,onLine=false
// 触发 early-kill,不再消费后续行。
func TestRunRPM_RealStdoutCaptured(t *testing.T) {
	writeFakeRPM(t, "#!/bin/sh\nfor i in $(seq 1 10); do echo \"S.5....T.  c /etc/f$i\"; done\n")
	var got []string
	_ = runRPM(context.Background(), func(b []byte) bool {
		got = append(got, string(b))
		return len(got) < 3 // 收 3 行后即止
	}, "-Va")
	if len(got) != 3 {
		t.Errorf("onLine=false 应提前杀子进程, got %d 行", len(got))
	}
}

// TestRunRPM_CtxDeadline ctx 超时优先返回 ctx.Err()(DeadlineExceeded)。
func TestRunRPM_CtxDeadline(t *testing.T) {
	writeFakeRPM(t, "#!/bin/sh\nexec sleep 5\n")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	got := runRPM(ctx, func([]byte) bool { return true }, "-Va")
	if !errors.Is(got, context.DeadlineExceeded) {
		t.Errorf("ctx 到期应返回 DeadlineExceeded, got %v", got)
	}
}

// TestRunRPM_MissingBinary 真 fork 路径:binary 缺失应 wrap 为 fs.ErrNotExist,
// isMissingBinary 可识别。
func TestRunRPM_MissingBinary(t *testing.T) {
	prev := rpmBinary
	rpmBinary = filepath.Join(t.TempDir(), "no-such-rpm")
	t.Cleanup(func() { rpmBinary = prev })
	got := runRPM(context.Background(), func([]byte) bool { return true }, "-Va")
	if !isMissingBinary(got) {
		t.Errorf("缺失 binary 应被 isMissingBinary 识别, got %v", got)
	}
}

// TestParseVerifyLine_NonNineByteFlag 短行(< 9 字节 flag)必须跳过,不误标 missing。
func TestParseVerifyLine_NonNineByteFlag(t *testing.T) {
	for _, line := range []string{"S.5", "missing", "hello world", "..?......"} {
		if _, ok := parseVerifyLine(line); ok {
			t.Errorf("行 %q 应跳过", line)
		}
	}
}

// TestResultsStructs_JSONShape 三个 Result 载荷的 JSON wire 形态:空 Entries 应为
// "entries":[] 而非 null,不依赖宿主状态。
func TestResultsStructs_JSONShape(t *testing.T) {
	t.Run("rpm_verify", func(t *testing.T) {
		res := VerifyResultPage{Entries: []VerifyResult{}}
		checkEmptyArray(t, res, "entries")
	})
	t.Run("rpm_unchanged", func(t *testing.T) {
		res := UnchangedResult{Packages: []string{}}
		checkEmptyArray(t, res, "packages")
	})
}

// --- helpers ---

// writeFakeRPM 生成可执行假 rpm 并临时覆写包级 binary。
func writeFakeRPM(t *testing.T, body string) {
	t.Helper()
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh 不可用,跳过真 exec 段")
	}
	scr := filepath.Join(t.TempDir(), "fake-rpm")
	if err := os.WriteFile(scr, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := rpmBinary
	rpmBinary = scr
	t.Cleanup(func() { rpmBinary = prev })
}

// summaryFakeRunner 是 rpm_summary 的假执行编排:
// - argv 含 "-qa" 时输出 3 行包名(rpm-qa 夹具头 3 行);
// - argv 含 "-Va" 时输出 3 行差异(去重后 3 条唯一路径);
// - argv 含 "-qf" 时输出 1 行归属包名(按调用次数递增)。
// 每次 run 通过闭包状态推进,不并行。
func summaryFakeRunner() execRunner {
	qaLines := []string{"bash", "coreutils", "dnf"}
	vaLines := []string{
		"S.5....T.  c /etc/dnf/dnf.conf",
		"S.5....T.  c /etc/yum.repos.d/base.repo",
		"..U......    /usr/bin/ls",
	}
	qfCalls := 0
	return func(_ context.Context, onLine func([]byte) bool, args ...string) error {
		if hasArg(args, "-qa", "") {
			for _, l := range qaLines {
				if !onLine([]byte(l)) {
					return nil
				}
			}
			return nil
		}
		if hasArg(args, "-Va", "") {
			for _, l := range vaLines {
				if !onLine([]byte(l)) {
					return nil
				}
			}
			return nil
		}
		if hasArg(args, "-qf", "") {
			qfCalls++
			_ = onLine([]byte("pkg" + strconv.Itoa(qfCalls)))
			return nil
		}
		return nil
	}
}

// checkEmptyArray 校验 Result 序列化后字段为空数组而非 null。
func checkEmptyArray(t *testing.T, v any, field string) {
	t.Helper()
	b, err := marshalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"`+field+`":[]`) {
		t.Errorf("wire 形态应为 %q 空数组, got: %s", field, string(b))
	}
}

// marshalJSON 是 json.Marshal 的测试替身(允许将来换 mock 时集中接入)。
func marshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// hasArg 检 argv 中是否含 key(可带紧随其后的 value)。
func hasArg(argv []string, key, val string) bool {
	for i, a := range argv {
		if a != key {
			continue
		}
		if val == "" {
			return true
		}
		if i+1 < len(argv) && argv[i+1] == val {
			return true
		}
	}
	return false
}

// argAfter 返回 argv 中 key 后紧跟的值(用于取 -qf 的路径)。
func argAfter(argv []string, key string) string {
	for i, a := range argv {
		if a == key && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

// ptrStr / ptrInt 测试构造指针参数。
func ptrStr(s string) *string { return &s }
func ptrInt(n int) *int       { return &n }

// --- review r1 回归(C1/C2/C3/I2/I3) ---

// nsFakeRunner 是 NAME 命名空间口径的"真 rpm 形态"假执行:按 argv 分发回放
// -qa / -Va / -qf 三档响应;-qf 是否带 queryformat 决定输出 NAME 还是 NEVRA,
// 钉住"统一命名空间"这条不可漂移的约束(C1 形态钉子)。
type nsFakeRunner struct {
	qaNames    []string
	vaLines    []string
	pathOwner  map[string][2]string // 路径 → [NAME, NEVRA],任一可空
	vaErr      error                // -Va 阶段的退出错误(nil 则 rc=0)
	qfArgvs    [][]string           // 记录每次 -qf 的 argv(断言 --queryformat)
	qaDuplicas bool                 // -qa 不去重(供 I2 dedup 检验用)
}

// runWithNs 是 nsFakeRunner 满足 execRunner 的入口。
func (r *nsFakeRunner) runWithNs(_ context.Context, onLine func([]byte) bool, args ...string) error {
	switch {
	case hasArg(args, "-qa", ""):
		names := r.qaNames
		if r.qaDuplicas {
			names = append(names, names...)
		}
		for _, l := range names {
			if !onLine([]byte(l)) {
				return nil
			}
		}
		return nil
	case hasArg(args, "-Va", ""):
		for _, l := range r.vaLines {
			if !onLine([]byte(l)) {
				return nil
			}
		}
		return r.vaErr
	case hasArg(args, "-qf", ""):
		r.qfArgvs = append(r.qfArgvs, append([]string(nil), args...))
		path := argAfter(args, "-qf")
		owner := r.pathOwner[path]
		// 命名空间口径:带 --queryformat 输出 NAME,缺省输出 NEVRA —— 与真
		// rpm -qf 在两种形态下的输出对齐,使旧实现(NEVRA)与新实现(NAME)
		// 在本 fake 下产生可区分的归属值。
		if hasArg(args, "--queryformat", "") {
			_ = onLine([]byte(owner[0]))
		} else {
			_ = onLine([]byte(owner[1]))
		}
		return nil
	}
	return nil
}

func newNsService(r *nsFakeRunner) *service {
	return &service{run: r.runWithNs, rpmTimeout: rpmTimeout}
}

// TestUnchanged_Full_NameNamespace C1 回归:rpm -qf 一律带 --queryformat '%{NAME}\n}',
// 归属与全集落在同一 NAME 命名空间;被改包必须从未改集排除。旧实现 `-qf <path>`
// 输出 NEVRA,落不进 NAME 全集,断言失败。
func TestUnchanged_Full_NameNamespace(t *testing.T) {
	fr := &nsFakeRunner{
		qaNames: []string{"bash", "coreutils", "dnf", "filesystem", "glibc", "rpm"},
		vaLines: []string{
			"S.5....T.  c /etc/dnf/dnf.conf",
			"..U......    /usr/bin/ls",
		},
		pathOwner: map[string][2]string{
			"/etc/dnf/dnf.conf": {"dnf", "dnf-4.14.2-1.el9.noarch"},
			"/usr/bin/ls":       {"coreutils", "coreutils-8.32-34.el9.x86_64"},
		},
	}
	svc := newNsService(fr)
	res, err := svc.Unchanged(context.Background(), UnchangedArgs{})
	if err != nil {
		t.Fatalf("Unchanged 应成功: %v", err)
	}
	want := map[string]bool{"bash": true, "filesystem": true, "glibc": true, "rpm": true}
	if res.TotalLines != len(want) {
		t.Errorf("TotalLines=%d, want %d (res=%+v)", res.TotalLines, len(want), res)
	}
	for _, p := range res.Packages {
		if !want[p] {
			t.Errorf("未改集含 NAME 命名空间外的项 %q: %v", p, res.Packages)
		}
		delete(want, p)
	}
	for p := range want {
		t.Errorf("未改集缺包 %q: %v", p, res.Packages)
	}
	// 钉死约束:归属查询必须带 --queryformat,否则输出 NEVRA 让本测试原地
	// 失败(上一段断言也会失败,这里是 belt-and-suspenders)。
	for i, argv := range fr.qfArgvs {
		if !hasArg(argv, "--queryformat", "") {
			t.Errorf("第 %d 次 -qf 未带 --queryformat,归属落 NEVRA 命名空间: %v", i, argv)
		}
	}
}

// TestSummary_ChangedPackagesTopIsName C1 回归:Summary.ChangedPackagesTop 必须是
// NAME 不是 NEVRA,否则下游消费者无法与包全集做差。
func TestSummary_ChangedPackagesTopIsName(t *testing.T) {
	fr := &nsFakeRunner{
		qaNames: []string{"bash", "coreutils", "dnf"},
		vaLines: []string{
			"S.5....T.  c /etc/dnf/dnf.conf",
			"..U......    /usr/bin/ls",
		},
		pathOwner: map[string][2]string{
			"/etc/dnf/dnf.conf": {"dnf", "dnf-4.14.2-1.el9.noarch"},
			"/usr/bin/ls":       {"coreutils", "coreutils-8.32-34.el9.x86_64"},
		},
	}
	svc := newNsService(fr)
	res, err := svc.Summary(context.Background())
	if err != nil {
		t.Fatalf("Summary 应成功: %v", err)
	}
	if res.ChangedPackages != 2 {
		t.Errorf("ChangedPackages=%d, want 2", res.ChangedPackages)
	}
	if len(res.ChangedPackagesTop) != 2 {
		t.Fatalf("ChangedPackagesTop=%v, want 2 项", res.ChangedPackagesTop)
	}
	want := map[string]bool{"dnf": true, "coreutils": true}
	for _, p := range res.ChangedPackagesTop {
		if !want[p] {
			t.Errorf("ChangedPackagesTop 含 NEVRA 形态 %q: %v", p, res.ChangedPackagesTop)
		}
		delete(want, p)
	}
	for p := range want {
		t.Errorf("ChangedPackagesTop 缺包 %q: %v", p, res.ChangedPackagesTop)
	}
}

// TestUnchanged_Full_Rc1DiffParsed C2 回归:-Va rc=1(文档语义"报告差异")不应上抛,
// 必须按 stdout 继续解析归属,被改包从未改集排除;旧实现把 rc=1 当 fork 失败
// 上抛,断言失败。
func TestUnchanged_Full_Rc1DiffParsed(t *testing.T) {
	fr := &nsFakeRunner{
		qaNames: []string{"bash", "coreutils", "dnf"},
		vaLines: []string{"S.5....T.  c /etc/dnf/dnf.conf"},
		pathOwner: map[string][2]string{
			"/etc/dnf/dnf.conf": {"dnf", "dnf-4.14.2-1.el9.noarch"},
		},
		vaErr: &execError{Code: 1, Stderr: ""},
	}
	svc := newNsService(fr)
	res, err := svc.Unchanged(context.Background(), UnchangedArgs{})
	if err != nil {
		t.Fatalf("rc=1(报告差异)非致命,不应上抛: %v", err)
	}
	for _, p := range res.Packages {
		if p == "dnf" {
			t.Errorf("rc=1 已声明存在差异,未改集不得含 dnf: %v", res.Packages)
		}
	}
	if !strings.Contains(res.Note, "差异") {
		t.Errorf("rc=1 应降级为'差异' note, got %q", res.Note)
	}
}

// TestVerifyAll_Rc2Propagated C3 回归:Verify(all=true) 下 rc=2 真故障必须上抛;
// 旧实现把 rc≥2 的 fatal 分支挂在 args.Package != nil 内,全量形态漏判,断言失败。
func TestVerifyAll_Rc2Propagated(t *testing.T) {
	svc, fr := newFakeService()
	fr.err = &execError{Code: 2, Stderr: "cannot open Packages database"}
	_, err := svc.Verify(context.Background(), VerifyArgs{All: true})
	if err == nil {
		t.Fatal("全量形态 rc≥2 真故障必须上抛(与单包形态一致)")
	}
	if !strings.Contains(err.Error(), "cannot open Packages database") {
		t.Errorf("错误应含 stderr: %q", err.Error())
	}
}

// TestSummary_TotalPackagesDedup I2 回归:rpm -qa 输出 multilib/kernel 多实例
// 时 NAME 重复出现,TotalPackages 必须按首次出现去重,否则多算。旧实现未去重。
func TestSummary_TotalPackagesDedup(t *testing.T) {
	fr := &nsFakeRunner{
		qaNames:    []string{"glibc", "glibc", "kernel", "kernel", "kernel", "bash"},
		pathOwner:  map[string][2]string{},
		qaDuplicas: true, // 让 fake 真的输出 12 行重复 NAME
	}
	svc := newNsService(fr)
	res, err := svc.Summary(context.Background())
	if err != nil {
		t.Fatalf("Summary 应成功: %v", err)
	}
	if res.TotalPackages != 3 {
		t.Errorf("TotalPackages=%d, want 3(去重后 glibc/kernel/bash)", res.TotalPackages)
	}
}

// TestHandleExecError I3 回归:rc 语义集中分类(none / 缺二进制 / rc=1 not-installed /
// rc=1 diff / rc≥2 / 非 *execError / ctx)的单元表。
func TestHandleExecError(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantNote  string // 子串匹配
		wantFatal bool
	}{
		{"nil", nil, "", false},
		{"missing-binary", &fs.PathError{Op: "fork/exec", Path: rpmBinary, Err: fs.ErrNotExist}, "不可用", false},
		{"rc1-not-installed", &execError{Code: 1, Stderr: "package latex is not installed"}, "不存在", false},
		{"rc1-diff", &execError{Code: 1, Stderr: ""}, "差异", false},
		{"rc2", &execError{Code: 2, Stderr: "cannot open Packages database"}, "", true},
		{"non-exec", errors.New("rpm 读取失败: broken pipe"), "", true},
		{"ctx-deadline", context.DeadlineExceeded, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			note, fatal := handleExecError(c.err)
			if fatal != c.wantFatal {
				t.Errorf("fatal=%v, want %v", fatal, c.wantFatal)
			}
			if c.wantNote == "" && note != "" {
				t.Errorf("wantNote='' 但 got %q", note)
			}
			if c.wantNote != "" && !strings.Contains(note, c.wantNote) {
				t.Errorf("note=%q 应含 %q", note, c.wantNote)
			}
		})
	}
}

// TestCollectChangedPackages_UnownedFiltered -qf 对无归属文件告警行(stdout 上的
// "file X is not owned by any package")必须过滤,不让告警文本落到已改包集合里;
// 旧实现用 HasSuffix("not owned") 命中不上该文本。
func TestCollectChangedPackages_UnownedFiltered(t *testing.T) {
	fr := &nsFakeRunner{
		vaLines: []string{"S.5....T.  c /tmp/unowned-file"},
		pathOwner: map[string][2]string{
			"/tmp/unowned-file": {"file /tmp/unowned-file is not owned by any package", "file /tmp/unowned-file is not owned by any package"},
		},
	}
	svc := newNsService(fr)
	changed := map[string]struct{}{}
	_, note, err := svc.collectChangedPackages(context.Background(), changed)
	if err != nil {
		t.Fatalf("无归属告警应非致命: %v", err)
	}
	if len(changed) != 0 {
		t.Errorf("无归属告警应被过滤, got changed=%v note=%q", changed, note)
	}
}

// TestCollectChangedPackages_AllArgsCarryQueryFormat 钉死约束:collectChangedPackages
// 对每条差异路径发起的 rpm -qf 都必须带 --queryformat 与 nameQueryFormat,否则
// 后续命名空间不收敛(参 TestUnchanged_Full_NameNamespace 的 belt-and-suspenders)。
func TestCollectChangedPackages_AllArgsCarryQueryFormat(t *testing.T) {
	fr := &nsFakeRunner{
		vaLines: []string{
			"S.5....T.  c /etc/dnf/dnf.conf",
			"..U......    /usr/bin/ls",
			"missing   /var/lib/orphan (Permission denied)",
		},
		pathOwner: map[string][2]string{
			"/etc/dnf/dnf.conf": {"dnf", "dnf-4.14.2-1.el9.noarch"},
			"/usr/bin/ls":       {"coreutils", "coreutils-8.32-34.el9.x86_64"},
			"/var/lib/orphan":   {"filesystem", "filesystem-3.16-2.el9.x86_64"},
		},
	}
	svc := newNsService(fr)
	_, _, err := svc.collectChangedPackages(context.Background(), map[string]struct{}{})
	if err != nil {
		t.Fatalf("collectChangedPackages 应成功: %v", err)
	}
	if len(fr.qfArgvs) != 3 {
		t.Fatalf("qfArgvs=%d, want 3(每条唯一路径一次)", len(fr.qfArgvs))
	}
	for i, argv := range fr.qfArgvs {
		if !hasArg(argv, "--queryformat", "") {
			t.Errorf("第 %d 次 -qf 缺 --queryformat: %v", i, argv)
		}
		if !hasArg(argv, "--queryformat", nameQueryFormat) {
			t.Errorf("第 %d 次 -qf --queryformat 值应为 nameQueryFormat=%q, got %v", i, nameQueryFormat, argv)
		}
	}
}
