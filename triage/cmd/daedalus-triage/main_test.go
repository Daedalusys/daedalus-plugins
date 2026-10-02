// triage MCP 服务器会话层测试:握手工具集与 5 工具端到端调用。所有工具
// 走真 CLI fork,允许真实机器上出现缺二进制/空集/降级 note —— 只校验工具
// 名与载荷结构稳定,不假设宿主状态。
package main

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectSession 建立内存内 MCP 会话;service 用生产装配(newService)以
// 走真实 fork 路径。
func connectSession(t *testing.T) (*mcp.ClientSession, context.Context, *service) {
	t.Helper()
	svc := newService()
	server := newServer(svc)
	ct, st := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, st) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "triage-test-client", Version: "0.0.0"}, nil)
	sess, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("MCP 握手失败: %v", err)
	}
	t.Cleanup(func() {
		if err := sess.Close(); err != nil {
			t.Errorf("会话关闭失败: %v", err)
		}
		if err := <-done; err != nil && !isCleanShutdown(err) {
			t.Errorf("服务器退出异常: %v", err)
		}
	})
	return sess, ctx, svc
}

// callTool 调用工具并返回原始文本与 isError。
func callTool(t *testing.T, s *mcp.ClientSession, ctx context.Context,
	tool string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
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

// TestHandshakeFiveTools 握手期 tools/list 必须返回 5 个工具,名称与
// manifest.tools 逐字一致(76 脚本构建期即核对该集合)。
func TestHandshakeFiveTools(t *testing.T) {
	sess, ctx, _ := connectSession(t)
	res, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	got := make([]string, 0, len(res.Tools))
	for _, tl := range res.Tools {
		got = append(got, tl.Name)
	}
	slices.Sort(got)
	want := []string{
		"boot_blame", "boot_critical_chain", "coredump_info",
		"coredumps_list", "last_boot_log",
	}
	if !slices.Equal(got, want) {
		t.Errorf("工具集 = %v\nwant %v", got, want)
	}
}

// TestToolsE2E 端到端跑 5 工具,验证返回 JSON 载荷结构稳定(允许空集 +
// note,不依赖真实宿主状态)。
func TestToolsE2E(t *testing.T) {
	sess, ctx, _ := connectSession(t)

	blameText, isErr := callTool(t, sess, ctx, "boot_blame", map[string]any{})
	if isErr {
		t.Fatalf("boot_blame 不应报错: %s", blameText)
	}
	var blame BootBlameResult
	if err := json.Unmarshal([]byte(blameText), &blame); err != nil {
		t.Fatalf("boot_blame 非 JSON: %v\n%s", err, blameText)
	}
	if blame.Entries == nil {
		t.Fatalf("boot_blame entries 应为 [] 而非 nil")
	}

	chainText, isErr := callTool(t, sess, ctx, "boot_critical_chain", map[string]any{})
	if isErr {
		t.Fatalf("boot_critical_chain 不应报错: %s", chainText)
	}
	var chain CriticalChainResult
	if err := json.Unmarshal([]byte(chainText), &chain); err != nil {
		t.Fatalf("boot_critical_chain 非 JSON: %v\n%s", err, chainText)
	}

	logText, isErr := callTool(t, sess, ctx, "last_boot_log", map[string]any{})
	if isErr {
		t.Fatalf("last_boot_log 不应报错: %s", logText)
	}
	var logs LastBootLogResult
	if err := json.Unmarshal([]byte(logText), &logs); err != nil {
		t.Fatalf("last_boot_log 非 JSON: %v\n%s", err, logText)
	}

	listText, isErr := callTool(t, sess, ctx, "coredumps_list", map[string]any{})
	if isErr {
		t.Fatalf("coredumps_list 不应报错: %s", listText)
	}
	var list CoredumpsListResult
	if err := json.Unmarshal([]byte(listText), &list); err != nil {
		t.Fatalf("coredumps_list 非 JSON: %v\n%s", err, listText)
	}

	infoText, isErr := callTool(t, sess, ctx, "coredump_info", map[string]any{"coredump_id": "1"})
	// coredump_info 无匹配 → 合法空集(非错误);ID 非法 → isError。
	if isErr {
		t.Fatalf("coredump_info 不应报错(ID=1): %s", infoText)
	}
	var info CoredumpInfoResult
	if err := json.Unmarshal([]byte(infoText), &info); err != nil {
		t.Fatalf("coredump_info 非 JSON: %v\n%s", err, infoText)
	}
	if info.CoredumpID != "1" {
		t.Errorf("coredump_id echo 错: %q", info.CoredumpID)
	}
}

// TestCoredumpInfo_ValidationRejectedBySchema ID 非法时由 service.Validate
// 拒绝,返回 isError=true 工具错误(不是 panic)。
func TestCoredumpInfo_ValidationRejectedBySchema(t *testing.T) {
	sess, ctx, _ := connectSession(t)
	text, isErr := callTool(t, sess, ctx, "coredump_info", map[string]any{"coredump_id": "-1"})
	if !isErr {
		t.Fatalf("非法 ID 应返回 isError,实际 %q", text)
	}
}
