package main

// server_test.go —— 走真实 MCP 会话(in-memory transport)验证两件构建期也要核对的事:
// 1) 注册的工具集与 manifest.tools 逐字一致(76 脚本构建期会做同样的核对);
// 2) tx_preview 端到端零副作用:只调只读的 service-observe,不落任何文件。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/audit"
	"github.com/Daedalusys/daedalus-sdk/autonomy"
)

func TestServerRegistersExactlyManifestTools(t *testing.T) {
	session, closeSession := connectTestSession(t, defaultConfig())
	defer closeSession()

	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var got []string
	for _, tool := range res.Tools {
		got = append(got, tool.Name)
	}
	slices.Sort(got)

	want := readManifestTools(t)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("注册工具 %v 与 manifest.tools %v 不一致(76 脚本会据此拒构建)", got, want)
	}
	if len(got) != 6 {
		t.Fatalf("工具数 = %d, 期望 6", len(got))
	}
}

func TestTxPreviewIsSideEffectFree(t *testing.T) {
	isolateRuntime(t)
	callLog := filepath.Join(t.TempDir(), "calls.log")
	installFakeTxScript(t, strings.Join([]string{
		`printf '%s\n' "$*" >> "$TX_CALL_LOG"`,
		`printf '%s\n' '{"unit":"demo.service","active_state":"inactive","unit_file_state":"enabled","enabled":true,"running":false,"known":true}'`,
	}, "\n"))
	t.Setenv("TX_CALL_LOG", callLog)

	cfg, err := loadRuntime(&strings.Builder{})
	if err != nil {
		t.Fatalf("loadRuntime: %v", err)
	}

	// 把 cwd 换到空目录:预览若偷偷落盘(审计/待办/临时文件),这里就会多出文件。
	workdir := t.TempDir()
	t.Chdir(workdir)

	session, closeSession := connectTestSession(t, cfg)
	defer closeSession()

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tx_preview",
		Arguments: map[string]any{
			"kind":          "service",
			"name":          "demo.service",
			"desired_state": "started",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tx_preview 不应报错: %v", res.Content)
	}
	if len(res.Content) != 1 {
		t.Fatalf("期望单文本块, 收到 %d 块", len(res.Content))
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("内容类型 = %T", res.Content[0])
	}
	var view previewView
	if err := json.Unmarshal([]byte(text.Text), &view); err != nil {
		t.Fatalf("返回不是 JSON: %v\n%s", err, text.Text)
	}
	if view.Tier != string(autonomy.TierAuto) {
		t.Fatalf("tier = %s, 期望 auto", view.Tier)
	}
	if want := []string{"systemctl", "--user", "start", "demo.service"}; !reflect.DeepEqual(view.Argv, want) {
		t.Fatalf("argv = %v, 期望 %v", view.Argv, want)
	}

	// 只允许只读子命令被调用:一个变更动词都不许出现。
	logData, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatalf("假 tx CLI 未被调用: %v", err)
	}
	if got := strings.TrimSpace(string(logData)); got != "service-observe --unit demo.service" {
		t.Fatalf("tx CLI 调用 = %q, 期望只读 service-observe", got)
	}

	entries, err := os.ReadDir(workdir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("tx_preview 产生了副作用文件: %v", entries)
	}
}

// 四个新工具经真实 MCP 调用返回结构化结果(不再是占位错误):非法 tx-id 在触碰
// CLI 之前当场拒绝,空日志/待办目录给出空列表。
func TestReadToolsAreWiredThroughMCPSession(t *testing.T) {
	isolateRuntime(t)
	root := t.TempDir()
	t.Setenv("DAEDALUS_TX_DIR", filepath.Join(root, "tx"))
	t.Setenv("DAEDALUS_PENDING_DIR", filepath.Join(root, "pending"))
	t.Setenv(audit.EnvLogPath, filepath.Join(root, "audit.jsonl"))

	session, closeSession := connectTestSession(t, defaultConfig())
	defer closeSession()

	call := func(name string, args map[string]any) *mcp.CallToolResult {
		t.Helper()
		res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("CallTool %s: %v", name, err)
		}
		return res
	}

	// tx_list:journal 目录没有事务 ⇒ 空列表,不是错误。
	res := call("tx_list", map[string]any{})
	if res.IsError {
		t.Fatalf("tx_list 不应报错: %+v", res.Content)
	}
	var listed listView
	if err := json.Unmarshal([]byte(textOf(t, res)), &listed); err != nil {
		t.Fatalf("tx_list 返回不是 JSON: %v", err)
	}
	if len(listed.Items) != 0 {
		t.Fatalf("tx_list items = %+v", listed.Items)
	}

	// tx_pending:待办目录不存在 ⇒ 空列表(且不创建目录)。
	res = call("tx_pending", map[string]any{})
	if res.IsError {
		t.Fatalf("tx_pending 不应报错: %+v", res.Content)
	}
	var pending pendingView
	if err := json.Unmarshal([]byte(textOf(t, res)), &pending); err != nil {
		t.Fatalf("tx_pending 返回不是 JSON: %v", err)
	}
	if len(pending.Items) != 0 {
		t.Fatalf("tx_pending items = %+v", pending.Items)
	}

	// tx_status / tx_rollback:非法 id 在触碰 CLI 之前就被拒(没有装假 CLI,
	// 真调 CLI 会因路径不存在而报另一种错误)。
	for _, name := range []string{"tx_status", "tx_rollback"} {
		res := call(name, map[string]any{"tx_id": "../etc/passwd"})
		if !res.IsError {
			t.Fatalf("%s 对非法 id 应标记 isError", name)
		}
		var payload map[string]string
		if err := json.Unmarshal([]byte(textOf(t, res)), &payload); err != nil {
			t.Fatalf("%s 返回不是结构化 JSON: %v", name, err)
		}
		if payload["error"] != codeInvalidTxID {
			t.Fatalf("%s error = %q, 期望 %q", name, payload["error"], codeInvalidTxID)
		}
	}
}

// textOf 取单文本块的正文。
func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("期望单文本块, 收到 %d 块", len(res.Content))
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("内容类型 = %T", res.Content[0])
	}
	return text.Text
}

// 拒绝面经真实 MCP 调用也必须是结构化原因:schema 不提前用 enum 拦,否则客户端
// 只能看到各家不同的 schema 校验文案,tier/required_scope 这类信息就丢了。
func TestTxPreviewReturnsStructuredRejection(t *testing.T) {
	session, closeSession := connectTestSession(t, defaultConfig())
	defer closeSession()

	for _, tc := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"kind", map[string]any{"kind": "package", "name": "nginx.service", "desired_state": "started"}, "unsupported_kind"},
		{"desired_state", map[string]any{"kind": "service", "name": "nginx.service", "desired_state": "reload"}, "unsupported_desired_state"},
		{"name", map[string]any{"kind": "service", "name": "backup.timer", "desired_state": "started"}, "invalid_name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
				Name:      "tx_preview",
				Arguments: tc.args,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !res.IsError {
				t.Fatal("拒绝应标记 isError")
			}
			text, ok := res.Content[0].(*mcp.TextContent)
			if !ok {
				t.Fatalf("内容类型 = %T", res.Content[0])
			}
			var payload map[string]string
			if err := json.Unmarshal([]byte(text.Text), &payload); err != nil {
				t.Fatalf("不是结构化 JSON: %v (%q)", err, text.Text)
			}
			if payload["error"] != tc.want {
				t.Fatalf("error = %q, 期望 %q", payload["error"], tc.want)
			}
		})
	}
}

func connectTestSession(t *testing.T, cfg *autonomy.Config) (*mcp.ClientSession, func()) {
	t.Helper()
	ctx := context.Background()
	server := newServer(cfg)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.0"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	return clientSession, func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	}
}

func readManifestTools(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "daedalus.plugin.json"))
	if err != nil {
		t.Fatalf("读 manifest: %v", err)
	}
	var manifest struct {
		Tools []string `json:"tools"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("解析 manifest: %v", err)
	}
	slices.Sort(manifest.Tools)
	return manifest.Tools
}
