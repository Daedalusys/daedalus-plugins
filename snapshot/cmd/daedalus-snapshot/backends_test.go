// snapshot_backends 的行为测试:探测结论只能来自「候选路径存在 + 版本命令
// 实际执行」两条证据,命令与文件系统全部经 seam 注入,单测不碰宿主。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/audit"
)

// TestMain 把审计链指向临时文件,避免测试期工具调用尝试写默认 /var/log。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "daedalus-snapshot-audit-main-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建审计临时目录失败: %v\n", err)
		os.Exit(1)
	}
	os.Setenv(audit.EnvLogPath, filepath.Join(dir, "audit.jsonl"))
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// fakeExec 脚本化命令替身(耗尽后重复最后一步)。
type fakeExec struct {
	calls [][]string
	steps []fakeStep
	idx   int
}

type fakeStep struct {
	stdout, stderr string
	code           int
	err            error
}

func (f *fakeExec) run(_ context.Context, name string, args []string) (string, string, int, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	s := f.steps[f.idx]
	if f.idx < len(f.steps)-1 {
		f.idx++
	}
	return s.stdout, s.stderr, s.code, s.err
}

// fakePathSet 返回只认给定路径集合的存在性替身。
func fakePathSet(paths ...string) func(string) bool {
	set := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		set[p] = struct{}{}
	}
	return func(p string) bool {
		_, ok := set[p]
		return ok
	}
}

// stubSeams 在测试期内替换存在性探测与命令执行两个 seam。
func stubSeams(t *testing.T, exists func(string) bool, run *fakeExec) {
	t.Helper()
	oldExists, oldExec := pathExists, execCommand
	pathExists = exists
	if run != nil {
		execCommand = run.run
	}
	t.Cleanup(func() { pathExists, execCommand = oldExists, oldExec })
}

// connectSession 建立内存内客户端/服务器会话。
func connectSession(t *testing.T) (*mcp.ClientSession, context.Context) {
	t.Helper()
	server := newServer()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "snapshot-test-client", Version: "0.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("MCP 握手失败: %v", err)
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Errorf("关闭会话失败: %v", err)
		}
		if err := <-serverDone; err != nil {
			t.Errorf("服务器退出异常: %v", err)
		}
	})
	return session, ctx
}

// callToolJSON 调用工具并把文本块解析为 JSON map。
func callToolJSON(t *testing.T, session *mcp.ClientSession, ctx context.Context, tool string, args map[string]any) map[string]any {
	t.Helper()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("tools/call %s 传输失败: %v", tool, err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("tools/call %s 无内容块", tool)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("tools/call %s 回包非文本: %T", tool, res.Content[0])
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("tools/call %s 回包非 JSON 对象: %v (%q)", tool, err, text.Text)
	}
	return out
}

// statusByName 取出指定后端的探测结论。
func statusByName(t *testing.T, statuses []backendStatus, name string) backendStatus {
	t.Helper()
	for _, st := range statuses {
		if st.Name == name {
			return st
		}
	}
	t.Fatalf("缺少后端 %q: %+v", name, statuses)
	return backendStatus{}
}

// TestBackendsAbsentToolingIsNotAssumed 候选全不存在时不得宣布可用,也不得
// 执行任何命令(没有二进制就没有证据)。
func TestBackendsAbsentToolingIsNotAssumed(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{code: 0}}}
	stubSeams(t, fakePathSet(), fe)

	statuses, recommended, supportsRollback := probeBackends(context.Background(), pathExists, execCommand)
	if len(fe.calls) != 0 {
		t.Errorf("候选未命中仍执行了命令: %v", fe.calls)
	}
	if recommended != "" || supportsRollback {
		t.Errorf("recommended = %q, supports_rollback = %v, want 空/false", recommended, supportsRollback)
	}
	for _, probe := range backendProbes {
		st := statusByName(t, statuses, probe.Name)
		if st.Available {
			t.Errorf("%s 不应可用", probe.Name)
		}
		if !strings.HasPrefix(st.Evidence, "未找到候选路径: ") {
			t.Errorf("%s evidence = %q, want 前缀「未找到候选路径: 」", probe.Name, st.Evidence)
		}
		for _, c := range probe.Candidates {
			if !strings.Contains(st.Evidence, c) {
				t.Errorf("%s evidence 缺候选路径 %q: %q", probe.Name, c, st.Evidence)
			}
		}
	}
}

// TestProbeExecFailureIsUnavailable 二进制存在但 --version 非零退出:不可用,
// 且证据必须带 rc 与 stderr 首行。
func TestProbeExecFailureIsUnavailable(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{
		stderr: "rsync: unrecognized option '--version'\nsecond line",
		code:   1,
	}}}
	stubSeams(t, fakePathSet("/usr/bin/rsync"), fe)

	statuses, recommended, supportsRollback := probeBackends(context.Background(), pathExists, execCommand)
	rsync := statusByName(t, statuses, "rsync")
	if rsync.Available {
		t.Errorf("rc≠0 时不得可用: %+v", rsync)
	}
	if !strings.Contains(rsync.Evidence, "rc=1") || !strings.Contains(rsync.Evidence, "unrecognized option") {
		t.Errorf("evidence = %q, want 含 rc=1 与 stderr 首行", rsync.Evidence)
	}
	if strings.Contains(rsync.Evidence, "second line") {
		t.Errorf("evidence 只应取 stderr 首行: %q", rsync.Evidence)
	}
	if recommended != "" || supportsRollback {
		t.Errorf("无可用后端时 recommended = %q, supports_rollback = %v", recommended, supportsRollback)
	}
}

// TestProbeEvidenceIsFirstLineOnly 多行版本输出只取首行,不把整份输出塞进回包。
func TestProbeEvidenceIsFirstLineOnly(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{
		stdout: "btrfs-progs v6.8\nsome extra line\n",
		code:   0,
	}}}
	stubSeams(t, fakePathSet("/usr/bin/btrfs"), fe)

	statuses, recommended, supportsRollback := probeBackends(context.Background(), pathExists, execCommand)
	btrfs := statusByName(t, statuses, "btrfs")
	if !btrfs.Available {
		t.Fatalf("rc=0 时应可用: %+v", btrfs)
	}
	if !strings.Contains(btrfs.Evidence, "btrfs-progs v6.8") || strings.Contains(btrfs.Evidence, "some extra line") {
		t.Errorf("evidence = %q, want 只含首行", btrfs.Evidence)
	}
	if recommended != "btrfs" || !supportsRollback {
		t.Errorf("recommended = %q, supports_rollback = %v", recommended, supportsRollback)
	}
	if len(fe.calls) != 1 || !slices.Equal(fe.calls[0], []string{"/usr/bin/btrfs", "--version"}) {
		t.Errorf("命令 = %v, want [[/usr/bin/btrfs --version]]", fe.calls)
	}
}

// TestBackendPriorityOrder 钉死推荐优先级:先写的后端优先,不按名字排序。
func TestBackendPriorityOrder(t *testing.T) {
	var candidates []string
	for _, probe := range backendProbes {
		candidates = append(candidates, probe.Candidates[0])
	}
	fe := &fakeExec{steps: []fakeStep{{stdout: "v1", code: 0}}}
	stubSeams(t, fakePathSet(candidates...), fe)

	_, recommended, _ := probeBackends(context.Background(), pathExists, execCommand)
	if recommended != backendProbes[0].Name {
		t.Errorf("recommended = %q, want %q", recommended, backendProbes[0].Name)
	}
}

// TestSnapshotBackendsPayloadEchoAndValidation 回显省略时补 "/",非法挂载点
// 在探测前拒绝。
func TestSnapshotBackendsPayloadEchoAndValidation(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{code: 0}}}
	stubSeams(t, fakePathSet(), fe)

	out := snapshotBackendsPayload(context.Background(), backendsIn{})
	list, ok := out["mountpoints"].([]string)
	if !ok || !slices.Equal(list, []string{"/"}) {
		t.Errorf("mountpoints = %v, want [\"/\"]", out["mountpoints"])
	}

	bad := snapshotBackendsPayload(context.Background(), backendsIn{Mountpoints: []string{""}})
	if _, ok := bad["error"]; !ok {
		t.Errorf("空挂载点应被拒绝: %v", bad)
	}
	if len(fe.calls) != 0 {
		t.Errorf("非法入参仍在探测: %v", fe.calls)
	}
}

// TestSnapshotBackendsToolEndToEnd 工具经 MCP 往返给出四个键。
func TestSnapshotBackendsToolEndToEnd(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{stdout: "btrfs-progs v6.8", code: 0}}}
	stubSeams(t, fakePathSet("/usr/bin/btrfs"), fe)

	session, ctx := connectSession(t)
	out := callToolJSON(t, session, ctx, "snapshot_backends", nil)
	for _, key := range []string{"mountpoints", "backends", "recommended", "supports_rollback"} {
		if _, ok := out[key]; !ok {
			t.Errorf("回包缺 %s: %v", key, out)
		}
	}
	if out["recommended"] != "btrfs" || out["supports_rollback"] != true {
		t.Errorf("recommended = %v, supports_rollback = %v", out["recommended"], out["supports_rollback"])
	}
}
