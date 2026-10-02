// journal 只读解析与外部 CLI 编排的单测:fixture 驱动的 JSON 解析、参数校验、
// 有界 follow、缺失降级与真 exec 贯通。
//
// 数据源固定指向包内 testdata/ 的 journalctl -o json 多行输出夹具,逐字段与
// 真实 journald 记录对齐;外部 CLI 一律经 execRunner 注入替身,测试零触碰宿主
// journald/journalctl(唯一例外是 TestRealExecHelper 用临时假脚本验证真 fork
// 路径,仍不读真实 journal)。
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

// loadLines 读 testdata 下 .jsonl 文件并按行拆分(去空行),模拟 journalctl
// 一行一条 JSON 的 stdout 形态。
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
// 时记录 aborted 并原地返回(模拟提前 kill 收工)。err 非 nil 时立即返回。
type fakeRunner struct {
	lines   [][]byte
	err     error
	aborted bool
	args    []string
}

func (f *fakeRunner) run(_ context.Context, onLine func([]byte) bool, args ...string) error {
	f.args = append([]string(nil), args...)
	if f.err != nil {
		return f.err
	}
	for _, line := range f.lines {
		if !onLine(line) {
			f.aborted = true
			return nil
		}
	}
	return nil
}

// newFakeService 装配一个挂 fakeRunner 的 service。
func newFakeService(lines ...[]byte) (*service, *fakeRunner) {
	fr := &fakeRunner{lines: lines}
	return &service{run: fr.run, followTimeout: journalFollowTimeout}, fr
}

// --- 解析层 ---

func TestParseEntry(t *testing.T) {
	line := []byte(`{"__REALTIME_TIMESTAMP":"1767268800123456","PRIORITY":"6","_SYSTEMD_UNIT":"mihomo.service","SYSLOG_IDENTIFIER":"mihomo","_PID":"1037","MESSAGE":"hello world"}`)
	got, ok := parseEntry(line)
	if !ok {
		t.Fatal("parseEntry 标准行失败")
	}
	if got.Timestamp != "2026-01-01T12:00:00.123456Z" {
		t.Errorf("Timestamp=%q, want 2026-01-01T12:00:00.123456Z(µs → RFC3339Nano)", got.Timestamp)
	}
	if got.Priority != "info" {
		t.Errorf("Priority=6 → info, got %q", got.Priority)
	}
	if got.Unit != "mihomo.service" || got.SyslogIdentifier != "mihomo" || got.PID != "1037" {
		t.Errorf("来源字段解析错: %+v", got)
	}
	if got.Message != "hello world" {
		t.Errorf("Message=%q", got.Message)
	}
}

// TestParseEntryPriorityNames 钉死 0..7 → emerg..debug 全枚举映射。
func TestParseEntryPriorityNames(t *testing.T) {
	for n := 0; n <= 7; n++ {
		line := []byte(`{"__REALTIME_TIMESTAMP":"1767273600000000","PRIORITY":"` + strconv.Itoa(n) + `"}`)
		e, ok := parseEntry(line)
		if !ok {
			t.Fatalf("PRIORITY=%d 应成功", n)
		}
		if want := priorityNames[strconv.Itoa(n)]; e.Priority != want {
			t.Errorf("PRIORITY=%d → %q, got %q", n, want, e.Priority)
		}
	}
}

// TestParseEntryByteArrayMessage journalctl 对非 UTF-8 MESSAGE 输出 JSON 字节
// 数字数组(systemd output_json 已知行为):必须还原为字节串而非丢条目。
func TestParseEntryByteArrayMessage(t *testing.T) {
	line := []byte(`{"__REALTIME_TIMESTAMP":"1767273600000000","MESSAGE":[104,105,255]}`)
	e, ok := parseEntry(line)
	if !ok {
		t.Fatal("字节数组 MESSAGE 应解析成功")
	}
	if want := string([]byte{104, 105, 255}); e.Message != want {
		t.Errorf("Message=%q, want %q", e.Message, want)
	}
}

// TestParseEntrySkipped 缺时间戳/非 JSON 跳过;PRIORITY 异常但时间戳有效保留
// (不因辅字段异常丢整条消息)。
func TestParseEntrySkipped(t *testing.T) {
	if _, ok := parseEntry([]byte(`{"MESSAGE":"x"}`)); ok {
		t.Error("缺 __REALTIME_TIMESTAMP 应跳过")
	}
	if _, ok := parseEntry([]byte(`this is not json`)); ok {
		t.Error("非 JSON 应跳过")
	}
	e, ok := parseEntry([]byte(`{"__REALTIME_TIMESTAMP":"1","PRIORITY":"oops","MESSAGE":"x"}`))
	if !ok {
		t.Fatal("有效时间戳应保留条目")
	}
	if e.Priority != "" {
		t.Errorf("未知 priority 应留空, got %q", e.Priority)
	}
}

// TestParseEntriesMixedFixture 好/坏混合夹具:解析好行、计数坏行、整体不崩。
func TestParseEntriesMixedFixture(t *testing.T) {
	entries, skipped := parseEntries(loadLines(t, "journal-mixed.jsonl"))
	if len(entries) != 2 || skipped != 2 {
		t.Errorf("entries=%d skipped=%d, want 2/2", len(entries), skipped)
	}
}

// --- journal_query ---

func TestQueryParseHits(t *testing.T) {
	svc, fr := newFakeService(loadLines(t, "journal-query.jsonl")...)
	res, err := svc.Query(context.Background(), QueryArgs{Unit: ptrStr("mihomo.service")})
	if err != nil {
		t.Fatalf("Query 应成功: %v", err)
	}
	if len(res.Entries) != 4 || res.SkippedLines != 0 || res.Note != "" {
		t.Errorf("结果异常: %+v", res)
	}
	for _, want := range [][2]string{{"-u", "mihomo.service"}, {"-o", "json"}, {"--no-pager", ""}, {"-q", ""}} {
		if !hasArg(fr.args, want[0], want[1]) {
			t.Errorf("argv 缺 %v: %v", want, fr.args)
		}
	}
}

// TestQueryLimitTruncation 超大输出截断:夹具供 200 行、limit=10,fake runner
// 无视 -n,故由 handler 兜底截尾到 10 条并标注 note。
func TestQueryLimitTruncation(t *testing.T) {
	lines := make([][]byte, 200)
	for i := range lines {
		lines[i] = []byte(`{"__REALTIME_TIMESTAMP":"1767273600` + pad6(i) + `","MESSAGE":"line-` + strconv.Itoa(i) + `"}`)
	}
	svc, fr := newFakeService(lines...)
	res, err := svc.Query(context.Background(), QueryArgs{Limit: ptrInt(10)})
	if err != nil {
		t.Fatalf("Query 应成功: %v", err)
	}
	if len(res.Entries) != 10 {
		t.Fatalf("Entries=%d, want 10", len(res.Entries))
	}
	if got := res.Entries[len(res.Entries)-1].Message; got != "line-199" {
		t.Errorf("应保留尾部最近条目,末条=%q", got)
	}
	if !strings.Contains(res.Note, "limit=10") {
		t.Errorf("Note 应标注截断: %q", res.Note)
	}
	if !hasArg(fr.args, "-n", "10") {
		t.Errorf("argv 缺 -n 10: %v", fr.args)
	}
}

// TestQueryValidation 参数形状校验:非法输入必须在拼 argv 前拒绝,且绝不抵达
// exec(journalctl 自身参数注入面)。
func TestQueryValidation(t *testing.T) {
	cases := []struct {
		name string
		args QueryArgs
		want string
	}{
		{"unit-empty", QueryArgs{Unit: ptrStr("")}, "unit 不能为空"},
		{"unit-injection", QueryArgs{Unit: ptrStr("foo; rm -rf /")}, "非法 unit"},
		{"unit-traversal", QueryArgs{Unit: ptrStr("foo..service")}, "路径遍历"},
		{"unit-leading-dash", QueryArgs{Unit: ptrStr("-foo.service")}, "非法 unit"},
		{"since-injection", QueryArgs{Since: ptrStr("2026-01-02; rm -rf /")}, "非法 since"},
		{"until-control", QueryArgs{Until: ptrStr("today\n--no-pager")}, "非法 until"},
		{"priority-unknown", QueryArgs{Priority: ptrStr("bogus")}, "priority"},
		{"grep-control", QueryArgs{Grep: ptrStr("a\x00b")}, "grep"},
		{"limit-zero", QueryArgs{Limit: ptrInt(0)}, "limit"},
		{"limit-huge", QueryArgs{Limit: ptrInt(20000)}, "limit"},
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

func TestQueryValidationDefaults(t *testing.T) {
	a := QueryArgs{}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if a.Limit == nil || *a.Limit != journalDefaultLimit {
		t.Errorf("缺省 limit 应为 %d, got %v", journalDefaultLimit, a.Limit)
	}
}

// TestQueryMissingBinaryInjected 注入 ENOENT 替身:降级为空集 + 显式 note,
// 不返回 error(不崩服)。
func TestQueryMissingBinaryInjected(t *testing.T) {
	svc := &service{
		followTimeout: journalFollowTimeout,
		run: func(_ context.Context, _ func([]byte) bool, _ ...string) error {
			return &fs.PathError{Op: "fork/exec", Path: journalctlBinary, Err: fs.ErrNotExist}
		},
	}
	res, err := svc.Query(context.Background(), QueryArgs{Unit: ptrStr("foo.service")})
	if err != nil {
		t.Fatalf("缺 binary 应降级而非报错: %v", err)
	}
	if len(res.Entries) != 0 || !strings.Contains(res.Note, "不可用") {
		t.Errorf("降级结果异常: %+v", res)
	}
}

// TestQueryRealMissingBinary 真 exec 路径的缺失降级:把包级 binary 指向不存在
// 的路径,验证 runJournalctl 的 ENOENT 被识别为降级信号。
func TestQueryRealMissingBinary(t *testing.T) {
	prev := journalctlBinary
	journalctlBinary = filepath.Join(t.TempDir(), "no-such-journalctl")
	t.Cleanup(func() { journalctlBinary = prev })

	res, err := newService().Query(context.Background(), QueryArgs{})
	if err != nil {
		t.Fatalf("缺 binary 应降级而非报错: %v", err)
	}
	if len(res.Entries) != 0 || !strings.Contains(res.Note, "不可用") {
		t.Errorf("降级结果异常: %+v", res)
	}
}

// TestQueryWireShapeEntriesEmptyArray Important #4 回归:Query 缺 binary 时
// Entries 必须为 []JournalEntry{} 而非 nil,否则 json 编码为 "entries":null,
// 与 Follow/LastBoot 的 "[]" 形态不一致,客户端解析踩空。
func TestQueryWireShapeEntriesEmptyArray(t *testing.T) {
	svc := &service{
		followTimeout: journalFollowTimeout,
		run: func(_ context.Context, _ func([]byte) bool, _ ...string) error {
			return &fs.PathError{Op: "fork/exec", Path: journalctlBinary, Err: fs.ErrNotExist}
		},
	}
	res, err := svc.Query(context.Background(), QueryArgs{Unit: ptrStr("foo.service")})
	if err != nil {
		t.Fatalf("缺 binary 应降级而非报错: %v", err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if got := string(raw["entries"]); got != "[]" {
		t.Errorf(`缺 binary 时 entries 应为 [] 而非 null, got %s`, got)
	}
}

// --- journal_follow(有界订阅)---

// TestFollowBoundedByCount 条目上限先到:夹具供 1500 行,应在第 1000 条处触发
// onLine=false(提前收工),aborted=true 证明不是收满再截。
func TestFollowBoundedByCount(t *testing.T) {
	lines := make([][]byte, 1500)
	for i := range lines {
		lines[i] = []byte(`{"__REALTIME_TIMESTAMP":"1767273600` + pad6(i) + `","MESSAGE":"e-` + strconv.Itoa(i) + `"}`)
	}
	svc, fr := newFakeService(lines...)
	res, err := svc.Follow(context.Background(), FollowArgs{Unit: "foo.service"})
	if err != nil {
		t.Fatalf("Follow 应成功: %v", err)
	}
	if len(res.Entries) != journalFollowMaxEntries {
		t.Errorf("Entries=%d, want %d", len(res.Entries), journalFollowMaxEntries)
	}
	if !fr.aborted {
		t.Error("应在 1000 条上限处提前中止 fakeRunner")
	}
	if !strings.Contains(res.Note, "上限") {
		t.Errorf("Note 应标注上限: %q", res.Note)
	}
}

// TestFollowBoundedByTimeout 超时上限先到:替身阻塞到 ctx 到期,Follow 以
// 可注入的短 followTimeout 验证 30s 有界机制,不真等 30s。
func TestFollowBoundedByTimeout(t *testing.T) {
	svc := &service{
		followTimeout: 50 * time.Millisecond,
		run: func(ctx context.Context, _ func([]byte) bool, _ ...string) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	res, err := svc.Follow(context.Background(), FollowArgs{Unit: "foo.service"})
	if err != nil {
		t.Fatalf("Follow 应成功: %v", err)
	}
	if len(res.Entries) != 0 {
		t.Errorf("超时应收空: %+v", res)
	}
	if !strings.Contains(res.Note, "上限") {
		t.Errorf("Note 应标注超时上限: %q", res.Note)
	}
}

func TestFollowArgv(t *testing.T) {
	svc, fr := newFakeService(loadLines(t, "journal-query.jsonl")...)
	if _, err := svc.Follow(context.Background(), FollowArgs{Unit: "sshd.service", Since: ptrStr("-1h")}); err != nil {
		t.Fatal(err)
	}
	for _, want := range [][2]string{{"--follow", ""}, {"-n", "0"}, {"-u", "sshd.service"}, {"--since=-1h", ""}} {
		if !hasArg(fr.args, want[0], want[1]) {
			t.Errorf("argv 缺 %v: %v", want, fr.args)
		}
	}
	if err := (FollowArgs{}).Validate(); err == nil {
		t.Error("unit 必填应拒绝空串")
	}
}

// --- journal_last_boot ---

func TestLastBoot(t *testing.T) {
	svc, fr := newFakeService(loadLines(t, "journal-lastboot.jsonl")...)
	res := svc.LastBoot(context.Background())
	if len(res.Entries) != 2 {
		t.Fatalf("Entries=%d, want 2", len(res.Entries))
	}
	for _, want := range [][2]string{{"-b", "-1"}, {"-n", strconv.Itoa(journalLastBootLimit)}, {"-o", "json"}} {
		if !hasArg(fr.args, want[0], want[1]) {
			t.Errorf("argv 缺 %v: %v", want, fr.args)
		}
	}
}

// --- 真 exec 原型贯通 ---

// TestRealExecHelper 写一个假 journalctl 脚本到临时目录并覆写包级 binary,
// 验证 runJournalctl 完整路径:argv 直发、stdin 置空、stdout 逐行回调。
func TestRealExecHelper(t *testing.T) {
	writeFakeJournalctl(t, "#!/bin/sh\ncat "+shellQuote(fixturePath(t, "journal-query.jsonl"))+"\n")

	var got [][]byte
	if err := runJournalctl(context.Background(), func(line []byte) bool {
		got = append(got, append([]byte(nil), line...))
		return true
	}, "-o", "json", "--no-pager", "-q", "-n", "10"); err != nil {
		t.Fatalf("runJournalctl 失败: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("stdout 行数=%d, want 4", len(got))
	}
}

// TestRealExecWrapsStderr 非零退出且 stderr 非空 → 错误须 wrap stderr 摘要。
func TestRealExecWrapsStderr(t *testing.T) {
	writeFakeJournalctl(t, "#!/bin/sh\necho 'fatal journal error' >&2\nexit 2\n")
	err := runJournalctl(context.Background(), func([]byte) bool { return true }, "-o", "json")
	if err == nil || !strings.Contains(err.Error(), "fatal journal error") {
		t.Errorf("错误应 wrap stderr, got %v", err)
	}
}

// TestRealExecExit1NoStderrPropagates 退出码 1 + 空 stderr 一律上抛(r1 修复:
// 删除"exit-1 = 无匹配"特例——journalctl 文档仅说"On success, 0; otherwise
// non-zero",本机实测无匹配退 0,特例会掩盖真故障)。
func TestRealExecExit1NoStderrPropagates(t *testing.T) {
	writeFakeJournalctl(t, "#!/bin/sh\nexit 1\n")
	err := runJournalctl(context.Background(), func([]byte) bool { return true }, "-o", "json")
	if err == nil {
		t.Fatal("exit 1 + 空 stderr 应上抛,不得静默吞成 nil(掩码 bug 回归)")
	}
	if isContextErr(err) {
		t.Errorf("退出码 1 非 ctx 问题, got %v", err)
	}
}

// TestRealExecExit2NoStderrPropagates 退出码 2 + 空 stderr(r1 修复前被掩码
// bug 吞成 nil 的典型场景):必须上抛,且非 ctx 错误。
func TestRealExecExit2NoStderrPropagates(t *testing.T) {
	writeFakeJournalctl(t, "#!/bin/sh\nexit 2\n")
	err := runJournalctl(context.Background(), func([]byte) bool { return true }, "-o", "json")
	if err == nil {
		t.Fatal("exit 2 + 空 stderr 应上抛,不得静默吞成 nil(掩码 bug 回归)")
	}
	if isContextErr(err) {
		t.Errorf("退出码 2 非 ctx 问题, got %v", err)
	}
}

// TestRealExecTimeoutReturnsCtxErr 真超时:脚本 sleep 5s,ctx 设 1s 超时。
// r1 修复前 runJournalctl 内部吞掉 *ExitError{Exited:false} → 假绿;
// 修复后必须返回 context.DeadlineExceeded,让调用方 errors.Is 可区分。
func TestRealExecTimeoutReturnsCtxErr(t *testing.T) {
	writeFakeJournalctl(t, "#!/bin/sh\nexec sleep 5\n")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := runJournalctl(ctx, func([]byte) bool { return true }, "-o", "json")
	if err == nil {
		t.Fatal("真超时应返回错误,不得假绿(旧掩码 bug)")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("超时应返回 context.DeadlineExceeded, got %v", err)
	}
}

// TestFollowRealTimeoutFollowsNote 真超时下 Follow 的"达到上限"note 必须
// 非空(Important #3 回归):runJournalctl 在 execCtx 到期返回
// DeadlineExceeded,Follow 命中 errors.Is 并补 note,不再是"死路"。
func TestFollowRealTimeoutFollowsNote(t *testing.T) {
	writeFakeJournalctl(t, "#!/bin/sh\nexec sleep 5\n")
	svc := &service{run: runJournalctl, followTimeout: 300 * time.Millisecond}
	res, err := svc.Follow(context.Background(), FollowArgs{Unit: "foo.service"})
	if err != nil {
		t.Fatalf("Follow 超时应收工而非报错: %v", err)
	}
	if strings.TrimSpace(res.Note) == "" {
		t.Errorf("真超时 Follow 应补 note(达到上限), got note=%q", res.Note)
	}
}

// TestRealExecEarlyStop 真 exec 下 onLine 返回 false 须杀掉子进程并正常收工
// (验证有界 follow 的提前中止在真 fork 下成立)。
func TestRealExecEarlyStop(t *testing.T) {
	writeFakeJournalctl(t, "#!/bin/sh\ni=0\nwhile [ $i -lt 100000 ]; do echo '{\"__REALTIME_TIMESTAMP\":\"1\"}'; i=$((i+1)); done\n")
	n := 0
	err := runJournalctl(context.Background(), func([]byte) bool {
		n++
		return n < 5
	}, "-o", "json")
	if err != nil {
		t.Fatalf("提前中止应正常收工: %v", err)
	}
	if n != 5 {
		t.Errorf("回调次数=%d, want 5", n)
	}
}

// isContextErr 判定错误是否为 ctx 超时/取消(用于区分"真退出码"与"ctx 到期")。
func isContextErr(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// --- helpers ---

// writeFakeJournalctl 生成可执行假 journalctl 并临时覆写包级 binary。
func writeFakeJournalctl(t *testing.T, body string) {
	t.Helper()
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh 不可用,跳过真 exec 段")
	}
	scr := filepath.Join(t.TempDir(), "fake-journalctl")
	if err := os.WriteFile(scr, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := journalctlBinary
	journalctlBinary = scr
	t.Cleanup(func() { journalctlBinary = prev })
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

// shellQuote 单引号包裹路径(shell 单引号内无转义,路径不含单引号时安全)。
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// pad6 把 0..999999 固定为 6 位数字串,保证生成的时间戳可解析且递增。
func pad6(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 6 {
		s = "0" + s
	}
	return s
}

func ptrStr(s string) *string { return &s }
func ptrInt(n int) *int       { return &n }
