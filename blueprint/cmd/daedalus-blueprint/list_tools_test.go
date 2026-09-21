package main

// list_tools_test.go —— blueprint_list / blueprint_inspect 的内存内 MCP 往返测试。
//
// 复用 daedalus-pkg/main_test.go 的 connectSession/callToolText 形态:
// 构造独立 app(newRegistry + 真实嵌入数据),经 mcp.NewInMemoryTransports
// 建立客户端会话,断言工具的结果 JSON 形状与 not-found 错误。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/blueprint"
)

// newTestApp 构造真实注册表(嵌入蓝图)+ app,供内存会话测试。
func newTestApp(t *testing.T) *app {
	t.Helper()
	reg, err := newRegistry(blueprint.MustLoad(EmbeddedBlueprints()))
	if err != nil {
		t.Fatalf("编译注册表失败: %v", err)
	}
	return newApp(reg)
}

// connectServer 建立内存内 MCP 会话(与 daedalus-pkg 同款)。
func connectServer(t *testing.T, a *app) (*mcp.ClientSession, context.Context) {
	t.Helper()
	server := newServer(a)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "blueprint-test-client", Version: "0.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("MCP 握手失败: %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		if err := <-serverDone; err != nil && !isCleanShutdown(err) {
			t.Errorf("服务器退出异常: %v", err)
		}
	})
	return session, ctx
}

// callText 调用工具并返回 (原始结果, 首个文本块内容)。
func callText(t *testing.T, session *mcp.ClientSession, ctx context.Context, tool string, args any) (*mcp.CallToolResult, string) {
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
	return res, text.Text
}

// TestListTool_Happy 断言 blueprint_list 返回 6 个蓝图的摘要且字段完整。
func TestListTool_Happy(t *testing.T) {
	a := newTestApp(t)
	session, ctx := connectServer(t, a)

	res, text := callText(t, session, ctx, "blueprint_list", map[string]any{})
	if res.IsError {
		t.Fatalf("blueprint_list 返回错误: %s", text)
	}
	var summaries []blueprintSummary
	if err := json.Unmarshal([]byte(text), &summaries); err != nil {
		t.Fatalf("结果非摘要数组(%v): %s", err, text)
	}
	if len(summaries) != 6 {
		t.Fatalf("蓝图表数量 = %d, want 6", len(summaries))
	}
	// 首项应为字典序第一个 id,且字段非空。
	first := summaries[0]
	if first.ID == "" || first.DisplayName == "" || first.Version == "" || first.Category == "" {
		t.Errorf("摘要字段不完整: %+v", first)
	}
	if first.ID != a.reg.orderedIDs()[0] {
		t.Errorf("首个 id = %q, want 字典序 %q", first.ID, a.reg.orderedIDs()[0])
	}
}

// TestInspectTool_Happy 断言 blueprint_inspect 返回完整详情且含 manifest 字段。
func TestInspectTool_Happy(t *testing.T) {
	a := newTestApp(t)
	session, ctx := connectServer(t, a)

	res, text := callText(t, session, ctx, "blueprint_inspect", map[string]any{"name": "nginx-vhost"})
	if res.IsError {
		t.Fatalf("blueprint_inspect 返回错误: %s", text)
	}
	var d blueprintDetail
	if err := json.Unmarshal([]byte(text), &d); err != nil {
		t.Fatalf("结果非 detail(%v): %s", err, text)
	}
	if d.ID != "nginx-vhost" {
		t.Errorf("id = %q, want nginx-vhost", d.ID)
	}
	if d.OutputPathTemplate == "" || d.ReloadService == "" {
		t.Errorf("output_path_template/reload_service 缺失: %+v", d)
	}
	if len(d.RequiredTools) == 0 {
		t.Errorf("required_tools 缺失: %+v", d)
	}
	if d.Schema == nil {
		t.Errorf("schema 未回显(期望 JSON 对象)")
	}
	if d.TemplatePreview == "" {
		t.Errorf("template 预览为空")
	}
	if !strings.Contains(d.ReadmeSummary, "Nginx 虚拟主机") {
		t.Errorf("README 摘要缺关键内容")
	}
}

// TestInspectTool_NotFound 断言 unknown name 返回明确错误。
func TestInspectTool_NotFound(t *testing.T) {
	a := newTestApp(t)
	session, ctx := connectServer(t, a)

	res, text := callText(t, session, ctx, "blueprint_inspect", map[string]any{"name": "no-such-blueprint"})
	if !res.IsError {
		t.Fatalf("unknown name 应返回错误, 得到: %s", text)
	}
	if !strings.Contains(text, "no-such-blueprint") {
		t.Errorf("错误文本应含蓝图名, 实际: %s", text)
	}
}
