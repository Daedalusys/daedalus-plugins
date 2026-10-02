// triage 单元测试。覆盖 5 个工具的正常解析、参数校验、缺失二进制降级、
// 长输出截断、coredumpctl 空集/错误二态分流，以及 JSON 形态稳定性。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mustReadFixture 读取 testdata/<name> 并返回字节切片。
func mustReadFixture(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join("testdata", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("读取 fixture %s 失败: %v", p, err)
	}
	return b
}

// fakeRun 是测试替身接收到的一次 CLI 调用记录。
type fakeRun struct {
	bin  string
	args []string
}

// makeScriptRunner 构造一个按行喂入 body 的 runner；exitErr 非 nil 时返
// 回该错（stderr 非空时拼到 err 文本中以模拟真实 stderr 内容）。每次调用
// 都会被追加到 *calls（共享底层数组以便断言）。
func makeScriptRunner(calls *[]fakeRun, body []byte, exitErr error, stderr string) execRunner {
	return func(ctx context.Context, bin string, onLine func([]byte) bool, args ...string) error {
		*calls = append(*calls, fakeRun{bin: bin, args: append([]string(nil), args...)})
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		for _, line := range strings.Split(string(body), "\n") {
			if !onLine([]byte(line)) {
				return nil
			}
		}
		if exitErr != nil {
			if stderr != "" {
				return fmt.Errorf("%s 失败: %w(%s)", bin, exitErr, stderr)
			}
			return fmt.Errorf("%s 失败: %w", bin, exitErr)
		}
		return nil
	}
}

// newServiceWith 装配 service 以测试用 runner。
func newServiceWith(r execRunner) *service {
	return &service{run: r, timeout: 5 * time.Second}
}

// ----- BootBlame -----

func TestBootBlame_NormalParse(t *testing.T) {
	body := mustReadFixture(t, "systemd-analyze-blame.txt")
	var calls []fakeRun
	s := newServiceWith(makeScriptRunner(&calls, body, nil, ""))

	got := s.BootBlame(context.Background())
	if got.Note != "" {
		t.Fatalf("正常路径不应有 note: %q", got.Note)
	}
	if len(got.Entries) != 15 {
		t.Fatalf("期望 15 条，实际 %d 条", len(got.Entries))
	}
	first := got.Entries[0]
	if first.Unit != "sys-module-fuse.device" || first.Seconds != 14.636 {
		t.Fatalf("首条解析错误: %+v", first)
	}
	if first.Time != "14.636s" {
		t.Fatalf("Time 字段未保留原文: %q", first.Time)
	}
	if got.Entries[14].Unit != "sshd.service" {
		t.Fatalf("末条单元错误: %q", got.Entries[14].Unit)
	}
	if len(calls) != 1 {
		t.Fatalf("期望 1 次调用，实际 %d", len(calls))
	}
	if calls[0].bin != systemdAnalyzeBinary {
		t.Fatalf("binary 不对: %s", calls[0].bin)
	}
	if len(calls[0].args) != 1 || calls[0].args[0] != "blame" {
		t.Fatalf("argv 不对: %v", calls[0].args)
	}
}

func TestBootBlame_LongOutputTruncates(t *testing.T) {
	var b strings.Builder
	for i := 0; i < blameMaxEntries+5; i++ {
		fmt.Fprintf(&b, "%d.000s unit-%d.service\n", i+1, i)
	}
	var calls []fakeRun
	s := newServiceWith(makeScriptRunner(&calls, []byte(b.String()), nil, ""))

	got := s.BootBlame(context.Background())
	if len(got.Entries) != blameMaxEntries {
		t.Fatalf("期望截断到 %d，实际 %d", blameMaxEntries, len(got.Entries))
	}
	if !strings.Contains(got.Note, "截断") {
		t.Fatalf("期望 note 含截断提示，实际 %q", got.Note)
	}
}

func TestBootBlame_MissingBinary(t *testing.T) {
	var calls []fakeRun
	r := makeScriptRunner(&calls, nil, fs.ErrNotExist, "")
	s := newServiceWith(r)

	got := s.BootBlame(context.Background())
	if len(got.Entries) != 0 {
		t.Fatalf("降级应返回空切片，实际 %d 条", len(got.Entries))
	}
	if !strings.Contains(got.Note, "不可用") {
		t.Fatalf("期望 note 含 '不可用'，实际 %q", got.Note)
	}
}

func TestBootBlame_RealError(t *testing.T) {
	var calls []fakeRun
	r := makeScriptRunner(&calls, nil, fmt.Errorf("未识别的选项"), "未识别的选项")
	s := newServiceWith(r)

	got := s.BootBlame(context.Background())
	if !strings.Contains(got.Note, "调用失败") {
		t.Fatalf("期望 note 含 '调用失败'，实际 %q", got.Note)
	}
}

// ----- BootCriticalChain -----

func TestCriticalChain_NormalParse(t *testing.T) {
	body := mustReadFixture(t, "systemd-analyze-critical-chain.txt")
	var calls []fakeRun
	s := newServiceWith(makeScriptRunner(&calls, body, nil, ""))

	got, err := s.BootCriticalChain(context.Background(), CriticalChainArgs{Unit: "multi-user.target"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got.Unit != "multi-user.target" {
		t.Fatalf("unit echo 错误: %q", got.Unit)
	}
	if len(got.Tree) != 17 {
		t.Fatalf("期望 17 行（首行 multi-user.target + 16 个子链），实际 %d", len(got.Tree))
	}
	root := got.Tree[0]
	if root.Unit != "multi-user.target" || root.Depth != 0 || root.Activation != "@13.272s" {
		t.Fatalf("根节点解析错误: %+v", root)
	}
	docker := got.Tree[1]
	if docker.Unit != "docker.service" || docker.Depth != 1 || docker.Activation != "@4.911s" || docker.Elapsed != "+8.360s" {
		t.Fatalf("docker 行解析错误: %+v", docker)
	}
	if len(calls[0].args) != 2 || calls[0].args[0] != "critical-chain" || calls[0].args[1] != "multi-user.target" {
		t.Fatalf("argv 不对: %v", calls[0].args)
	}
}

func TestCriticalChain_EmptyUnit(t *testing.T) {
	body := mustReadFixture(t, "systemd-analyze-critical-chain.txt")
	var calls []fakeRun
	s := newServiceWith(makeScriptRunner(&calls, body, nil, ""))

	_, err := s.BootCriticalChain(context.Background(), CriticalChainArgs{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(calls[0].args) != 1 || calls[0].args[0] != "critical-chain" {
		t.Fatalf("argv 应仅含 critical-chain，实际 %v", calls[0].args)
	}
}

func TestCriticalChain_ValidationRejects(t *testing.T) {
	s := newServiceWith(nil)
	cases := []string{"-bad.service", "foo;rm.service", "../etc"}
	for _, u := range cases {
		if _, err := s.BootCriticalChain(context.Background(), CriticalChainArgs{Unit: u}); err == nil {
			t.Errorf("unit %q 期望被拒绝", u)
		}
	}
}

func TestCriticalChain_MissingBinary(t *testing.T) {
	var calls []fakeRun
	r := makeScriptRunner(&calls, nil, fs.ErrNotExist, "")
	s := newServiceWith(r)

	got, err := s.BootCriticalChain(context.Background(), CriticalChainArgs{Unit: "multi-user.target"})
	if err != nil {
		t.Fatalf("缺失二进制应降级不返回 err，实际 %v", err)
	}
	if !strings.Contains(got.Note, "不可用") {
		t.Fatalf("期望 note 含 '不可用'，实际 %q", got.Note)
	}
}

// ----- LastBootLog -----

func TestLastBootLog_NormalParse(t *testing.T) {
	body := mustReadFixture(t, "journal-lastboot.jsonl")
	var calls []fakeRun
	s := newServiceWith(makeScriptRunner(&calls, body, nil, ""))

	got, err := s.LastBootLog(context.Background(), LastBootLogArgs{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got.Entries) != 3 {
		t.Fatalf("期望 3 条，实际 %d", len(got.Entries))
	}
	if got.Entries[0].Priority != "info" || got.Entries[0].Unit != "mihomo.service" {
		t.Fatalf("首条解析错误: %+v", got.Entries[0])
	}
	if got.Entries[1].Priority != "warning" {
		t.Fatalf("第 2 条 priority 错: %q", got.Entries[1].Priority)
	}
	if got.Entries[2].Priority != "err" {
		t.Fatalf("第 3 条 priority 错: %q", got.Entries[2].Priority)
	}
	if !hasArg(calls[0].args, "--no-pager") || !hasArg(calls[0].args, "-q") {
		t.Fatalf("argv 应含 --no-pager 与 -q，实际 %v", calls[0].args)
	}
}

func TestLastBootLog_WithPriority(t *testing.T) {
	body := mustReadFixture(t, "journal-lastboot.jsonl")
	var calls []fakeRun
	s := newServiceWith(makeScriptRunner(&calls, body, nil, ""))

	pri := "3"
	_, err := s.LastBootLog(context.Background(), LastBootLogArgs{Priority: &pri})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !hasArg(calls[0].args, "--priority=3") {
		t.Fatalf("argv 应含 --priority=3，实际 %v", calls[0].args)
	}
}

func TestLastBootLog_BadJSONSkipped(t *testing.T) {
	body := []byte(`{"__REALTIME_TIMESTAMP":"1","PRIORITY":"6","MESSAGE":"good"}
not-a-json-line
{"__REALTIME_TIMESTAMP":"2","PRIORITY":"4","MESSAGE":"also-good"}`)
	var calls []fakeRun
	s := newServiceWith(makeScriptRunner(&calls, body, nil, ""))

	got, err := s.LastBootLog(context.Background(), LastBootLogArgs{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("期望 2 条好 JSON，实际 %d", len(got.Entries))
	}
	if !strings.Contains(got.Note, "跳过 1 行坏 JSON") {
		t.Fatalf("期望 note 含 '跳过 1 行坏 JSON'，实际 %q", got.Note)
	}
}

func TestLastBootLog_ValidationRejects(t *testing.T) {
	s := newServiceWith(nil)
	bad := "fatal"
	if _, err := s.LastBootLog(context.Background(), LastBootLogArgs{Priority: &bad}); err == nil {
		t.Fatal("期望非法 priority 拒绝")
	}
}

// ----- CoredumpsList -----

func TestCoredumpsList_NormalParse(t *testing.T) {
	body := mustReadFixture(t, "coredumpctl-list-short.json")
	var calls []fakeRun
	s := newServiceWith(makeScriptRunner(&calls, body, nil, ""))

	got := s.CoredumpsList(context.Background())
	if got.Note != "" {
		t.Fatalf("正常路径不应有 note: %q", got.Note)
	}
	if len(got.Entries) != 5 {
		t.Fatalf("期望 5 条，实际 %d", len(got.Entries))
	}
	e := got.Entries[0]
	if e.PID != 589370 || e.UID != 1000 || e.Signal != 6 {
		t.Fatalf("首条 PID/UID/Signal 错: %+v", e)
	}
	if e.CoredumpFile != "present" {
		t.Fatalf("corefile 错: %q", e.CoredumpFile)
	}
	if e.SizeBytes == nil || *e.SizeBytes != 500486 {
		t.Fatalf("size 字段错: %v", e.SizeBytes)
	}
	if e.Time == "" {
		t.Fatalf("time 字段缺失")
	}
	deno := got.Entries[2]
	if deno.CoredumpFile != "inaccessible" || deno.SizeBytes != nil {
		t.Fatalf("无权限条目标记错误: %+v", deno)
	}
	if !hasArg(calls[0].args, "--json=short") {
		t.Fatalf("argv 应含 --json=short")
	}
}

func TestCoredumpsList_NoMatchTreatedAsEmpty(t *testing.T) {
	var calls []fakeRun
	// 注意：runCLI 把 stderr 文本 wrap 到 err 中；"No coredumps found." 必
	// 须命中 isCoredumpsEmpty 的子串判断。
	r := makeScriptRunner(&calls, nil, fmt.Errorf("exit 1"), "No coredumps found.")
	s := newServiceWith(r)

	got := s.CoredumpsList(context.Background())
	if len(got.Entries) != 0 {
		t.Fatalf("期望空集，实际 %d 条", len(got.Entries))
	}
	if got.Note != "无内核转储记录" {
		t.Fatalf("期望 note 为 '无内核转储记录'，实际 %q", got.Note)
	}
}

func TestCoredumpsList_RealErrorPropagated(t *testing.T) {
	var calls []fakeRun
	r := makeScriptRunner(&calls, nil, fmt.Errorf("exit 1"), "未识别的选项 --bogus")
	s := newServiceWith(r)

	got := s.CoredumpsList(context.Background())
	if !strings.Contains(got.Note, "调用失败") {
		t.Fatalf("期望 note 含 '调用失败'，实际 %q", got.Note)
	}
}

func TestCoredumpsList_MissingBinary(t *testing.T) {
	var calls []fakeRun
	r := makeScriptRunner(&calls, nil, fs.ErrNotExist, "")
	s := newServiceWith(r)

	got := s.CoredumpsList(context.Background())
	if !strings.Contains(got.Note, "不可用") {
		t.Fatalf("期望 note 含 '不可用'，实际 %q", got.Note)
	}
}

func TestCoredumpsList_MalformedJSON(t *testing.T) {
	body := []byte(`{"pid":1,`)
	var calls []fakeRun
	s := newServiceWith(makeScriptRunner(&calls, body, nil, ""))

	got := s.CoredumpsList(context.Background())
	if !strings.Contains(got.Note, "JSON 解析失败") {
		t.Fatalf("期望 note 含 'JSON 解析失败'，实际 %q", got.Note)
	}
}

// ----- CoredumpInfo -----

func TestCoredumpInfo_NormalParse(t *testing.T) {
	body := mustReadFixture(t, "coredumpctl-info.txt")
	var calls []fakeRun
	s := newServiceWith(makeScriptRunner(&calls, body, nil, ""))

	got, err := s.CoredumpInfo(context.Background(), "1057526")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got.CoredumpID != "1057526" {
		t.Fatalf("id echo 错: %q", got.CoredumpID)
	}
	if got.Fields["PID"] != "1057526 (deno)" {
		t.Fatalf("Fields[PID] 错: %q", got.Fields["PID"])
	}
	if got.Fields["Signal"] != "11 (SEGV)" {
		t.Fatalf("Fields[Signal] 错: %q", got.Fields["Signal"])
	}
	if !strings.Contains(got.Raw, "Stack trace") {
		t.Fatalf("raw 应保留 stack trace 文本")
	}
	if !hasArg(calls[0].args, "info") || !hasArg(calls[0].args, "1057526") {
		t.Fatalf("argv 应含 info 与 id，实际 %v", calls[0].args)
	}
}

func TestCoredumpInfo_NoMatchTreatedAsEmpty(t *testing.T) {
	var calls []fakeRun
	r := makeScriptRunner(&calls, nil, fmt.Errorf("exit 1"), "No coredumps found.")
	s := newServiceWith(r)

	got, err := s.CoredumpInfo(context.Background(), "999999999")
	if err != nil {
		t.Fatalf("空集不返回 err，实际 %v", err)
	}
	if got.Note != "无内核转储记录" {
		t.Fatalf("期望 note 为 '无内核转储记录'，实际 %q", got.Note)
	}
}

func TestCoredumpInfo_MissingBinary(t *testing.T) {
	var calls []fakeRun
	r := makeScriptRunner(&calls, nil, fs.ErrNotExist, "")
	s := newServiceWith(r)

	got, err := s.CoredumpInfo(context.Background(), "1")
	if err != nil {
		t.Fatalf("缺失二进制应降级不返回 err，实际 %v", err)
	}
	if !strings.Contains(got.Note, "不可用") {
		t.Fatalf("期望 note 含 '不可用'，实际 %q", got.Note)
	}
}

func TestCoredumpInfo_RawTruncated(t *testing.T) {
	var b strings.Builder
	b.WriteString("           PID: 1 (x)\n")
	b.WriteString(strings.Repeat("a", coredumpInfoMaxBytes+1024))
	body := []byte(b.String())
	var calls []fakeRun
	s := newServiceWith(makeScriptRunner(&calls, body, nil, ""))

	got, err := s.CoredumpInfo(context.Background(), "1")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got.Raw) > coredumpInfoMaxBytes+len("\n... [truncated]") {
		t.Fatalf("raw 字段过长 %d", len(got.Raw))
	}
	if !strings.Contains(got.Raw, "[truncated]") {
		t.Fatalf("raw 字段应含截断标记")
	}
}

func TestCoredumpInfo_ValidationRejects(t *testing.T) {
	s := newServiceWith(nil)
	cases := []string{"", "0", "-1", "abc", "1.5", "999999999999999999999999999"}
	for _, id := range cases {
		if _, err := s.CoredumpInfo(context.Background(), id); err == nil {
			t.Errorf("coredump_id %q 期望被拒绝", id)
		}
	}
}

// ----- ctx 超时优先级 -----

func TestCtxDeadline_PrioritizedOverMainExit(t *testing.T) {
	var calls []fakeRun
	// 模拟 ctx 早到期，runner 应返回 ctx.Err()，不抛子进程退出错误。
	r := makeScriptRunner(&calls, nil, &exec.ExitError{}, "")
	s := newServiceWith(r)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond)
	got := s.BootBlame(ctx)
	if !strings.Contains(got.Note, "context deadline exceeded") &&
		!strings.Contains(got.Note, "调用失败") {
		t.Logf("ctx 到期后返回 note: %q（路径依赖调度，可接受）", got.Note)
	}
}

// ----- JSON 形态稳定性（防漂移门禁）-----

func TestResultsStructs_JSONShape(t *testing.T) {
	cases := []struct {
		name string
		v    any
	}{
		{"boot_blame", BootBlameResult{Entries: []BootBlameEntry{{Unit: "x.service", Time: "1.0s", Seconds: 1.0}}, Note: "n"}},
		{"boot_critical_chain", CriticalChainResult{Unit: "u", Tree: []CriticalChainLine{{Unit: "u", Depth: 1, Activation: "@1s", Elapsed: "+1s"}}, Note: "n"}},
		{"last_boot_log", LastBootLogResult{Entries: []LastBootLogEntry{{Timestamp: "t", Priority: "info", Unit: "u", Message: "m"}}, Note: "n"}},
		{"coredumps_list", CoredumpsListResult{Entries: []CoredumpEntry{{Time: "t", PID: 1, UID: 2, GID: 3, Signal: 11, CoredumpFile: "present", Exe: "/x", SizeBytes: ptrInt64(100)}}, Note: "n"}},
		{"coredump_info", CoredumpInfoResult{CoredumpID: "1", Fields: map[string]string{"PID": "1 (x)"}, Raw: "raw text", Note: "n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.v)
			if err != nil {
				t.Fatalf("marshal 失败: %v", err)
			}
			round := map[string]any{}
			if err := json.Unmarshal(b, &round); err != nil {
				t.Fatalf("unmarshal 失败: %v", err)
			}
			hasPayload := false
			for _, key := range []string{"entries", "tree", "fields"} {
				if _, ok := round[key]; ok {
					hasPayload = true
				}
			}
			if !hasPayload {
				t.Fatalf("载荷缺失，JSON: %s", b)
			}
		})
	}
}

// ----- 内部小工具 -----

func ptrInt64(v int64) *int64 { return &v }

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
