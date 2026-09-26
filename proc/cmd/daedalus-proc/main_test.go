// proc 服务器 MCP 会话层测试:握手工具集、五工具端到端调用与错误面。
// 数据源经 DAEDALUS_PROC_ROOT 指向伪 /proc 夹具,测试零触碰真实 /proc。
package main

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectSession 建立内存内 MCP 会话(同 cmd/daedalus-pkg 实证形态),
// 并在测试结束时校验会话与服务器均干净退出。
func connectSession(t *testing.T) (*mcp.ClientSession, context.Context) {
	t.Helper()
	server := newServer()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "proc-test-client", Version: "0.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("MCP 握手失败: %v", err)
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Errorf("会话关闭失败: %v", err)
		}
		if err := <-serverDone; err != nil && !isCleanShutdown(err) {
			t.Errorf("服务器退出异常: %v", err)
		}
	})
	return session, ctx
}

// callProc 调用工具并返回原始文本与 isError 标记。
func callProc(t *testing.T, session *mcp.ClientSession, ctx context.Context,
	tool string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s) 传输失败: %v", tool, err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("%s 结果块数 = %d", tool, len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s 结果块非 TextContent: %T", tool, res.Content[0])
	}
	return tc.Text, res.IsError
}

func callProcJSON[T any](t *testing.T, session *mcp.ClientSession, ctx context.Context,
	tool string, args map[string]any) T {
	t.Helper()
	text, isErr := callProc(t, session, ctx, tool, args)
	if isErr {
		t.Fatalf("%s 意外报错: %s", tool, text)
	}
	var out T
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("%s 输出非 JSON: %v\n%s", tool, err, text)
	}
	return out
}

func TestNewServer_HandshakeFiveTools(t *testing.T) {
	session, ctx := connectSession(t)
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	got := make([]string, 0, len(res.Tools))
	for _, tl := range res.Tools {
		got = append(got, tl.Name)
	}
	slices.Sort(got)
	want := []string{"proc_cgroup", "proc_fds", "proc_list", "proc_listen", "proc_tree"}
	if !slices.Equal(got, want) {
		t.Errorf("工具集 = %v, want %v", got, want)
	}
}

func TestProcListE2E(t *testing.T) {
	t.Setenv(EnvProcRoot, makeProcFixture(t))
	session, ctx := connectSession(t)

	view := callProcJSON[procListView](t, session, ctx, "proc_list", map[string]any{})
	if view.Total != 4 || view.Skipped != 0 || len(view.Processes) != 4 {
		t.Fatalf("proc_list 基线错误: %+v", view)
	}
	filtered := callProcJSON[procListView](t, session, ctx, "proc_list",
		map[string]any{"filter": "kthread"})
	if filtered.Total != 1 || filtered.Processes[0].PID != 2 {
		t.Errorf("filter=kthread = %+v", filtered)
	}
}

func TestProcTreeE2E(t *testing.T) {
	t.Setenv(EnvProcRoot, makeProcFixture(t))
	session, ctx := connectSession(t)

	view := callProcJSON[procTreeView](t, session, ctx, "proc_tree", map[string]any{})
	if view.RootPID != 1 || view.TotalProcesses != 4 || len(view.Tree.Children) != 2 {
		t.Fatalf("proc_tree 基线错误: %+v", view)
	}
	sub := callProcJSON[procTreeView](t, session, ctx, "proc_tree", map[string]any{"root_pid": 40})
	if sub.Tree.PID != 40 || len(sub.Tree.Children) != 1 || sub.Tree.Children[0].Name != "worker with space" {
		t.Errorf("root_pid=40 子树错误: %+v", sub.Tree)
	}
}

func TestProcFdsE2E(t *testing.T) {
	t.Setenv(EnvProcRoot, makeProcFixture(t))
	session, ctx := connectSession(t)

	view := callProcJSON[procFdsView](t, session, ctx, "proc_fds", map[string]any{"pid": 40})
	if view.Total != 5 || view.Unreadable != 0 {
		t.Fatalf("proc_fds 基线错误: %+v", view)
	}
	sockets := callProcJSON[procFdsView](t, session, ctx, "proc_fds",
		map[string]any{"pid": 40, "kinds": []string{"socket"}})
	if sockets.Total != 2 || sockets.Entries[0].Target != "socket:[555]" {
		t.Errorf("kinds=[socket] = %+v", sockets)
	}
}

func TestProcListenE2E(t *testing.T) {
	t.Setenv(EnvProcRoot, makeProcFixture(t))
	session, ctx := connectSession(t)

	tcp := callProcJSON[procListenView](t, session, ctx, "proc_listen", map[string]any{})
	if tcp.Scanned != 3 || tcp.Unowned != 1 || tcp.Proto != "tcp" {
		t.Fatalf("proc_listen 基线错误: %+v", tcp.listenResult)
	}
	one := callProcJSON[procListenView](t, session, ctx, "proc_listen",
		map[string]any{"port": 8080, "proto": "tcp"})
	if one.Total() != 1 || one.Entries[0].Names[0] != "nginx" {
		t.Errorf("port=8080 = %+v", one.listenResult)
	}
	udp := callProcJSON[procListenView](t, session, ctx, "proc_listen",
		map[string]any{"proto": "udp"})
	if udp.Scanned != 1 || udp.Entries[0].State != "UNCONN" {
		t.Errorf("proto=udp = %+v", udp.listenResult)
	}
}

func (v procListenView) Total() int { return len(v.Entries) }

func TestProcCgroupE2E(t *testing.T) {
	t.Setenv(EnvProcRoot, makeProcFixture(t))
	session, ctx := connectSession(t)
	view := callProcJSON[procCgroupView](t, session, ctx, "proc_cgroup", map[string]any{"pid": 40})
	if view.Unit != "nginx.service" || view.Cgroups[""] != "/system.slice/nginx.service" {
		t.Errorf("proc_cgroup = %+v", view)
	}
}

// TestProcErrorSurface 错误面钉死:参数校验与根不可读的报错形态
// (isError + "Error executing tool <name>: " 前缀)。
func TestProcErrorSurface(t *testing.T) {
	t.Setenv(EnvProcRoot, makeProcFixture(t))
	session, ctx := connectSession(t)
	long := strings.Repeat("x", 129)
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"proc_list", map[string]any{"filter": ""}, "Error executing tool proc_list: "},
		{"proc_list", map[string]any{"filter": long}, "长度须在"},
		{"proc_list", map[string]any{"filter": "a\nb"}, "控制字符"},
		{"proc_tree", map[string]any{"root_pid": -3}, "正整数"},
		{"proc_tree", map[string]any{"root_pid": 999}, "不存在"},
		{"proc_fds", map[string]any{"pid": 0}, "Error executing tool proc_fds: "},
		{"proc_fds", map[string]any{"pid": 1, "kinds": []string{"tty"}}, "enum: tty"},
		{"proc_fds", map[string]any{"pid": 99999}, "失败"},
		{"proc_listen", map[string]any{"proto": "icmp"}, "enum: icmp"},
		{"proc_listen", map[string]any{"port": 70000}, "65535"},
		{"proc_cgroup", map[string]any{"pid": -1}, "Error executing tool proc_cgroup: "},
	} {
		text, isErr := callProc(t, session, ctx, tc.tool, tc.args)
		if !isErr {
			t.Errorf("%v %v 应报错,得 %s", tc.tool, tc.args, text)
			continue
		}
		if !strings.Contains(text, tc.want) {
			t.Errorf("%v %v 报错文案缺 %q: %s", tc.tool, tc.args, tc.want, text)
		}
	}
}

func TestProcRootMissingError(t *testing.T) {
	t.Setenv(EnvProcRoot, "/nonexistent-proc-root-xyz")
	session, ctx := connectSession(t)
	text, isErr := callProc(t, session, ctx, "proc_list", map[string]any{})
	if !isErr || !strings.Contains(text, "不可读") {
		t.Errorf("根缺失应报错 不可读: %s", text)
	}
}
