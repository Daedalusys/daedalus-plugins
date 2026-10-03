// integrity MCP 服务器会话层测试:握手工具集与 3 工具端到端调用。所有工具走
// 真 CLI fork,允许真实机器上出现缺二进制/非 root 降级 note —— 只校验工具名
// 与载荷结构稳定,不假设宿主状态。
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
// 走真实 fork 路径。会话级 60s 上限覆盖 rpm_verify(rpm -V) 等非网络、但需
// 落盘元数据查询的 fork;rpm -Va 在大包集群上实测 60s+ 是常态,不在 E2E
// 范围。
func connectSession(t *testing.T) (*mcp.ClientSession, context.Context, *service) {
	t.Helper()
	svc := newService()
	server := newServer(svc)
	ct, st := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, st) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "integrity-test-client", Version: "0.0.0"}, nil)
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

// TestHandshakeThreeTools 握手期 tools/list 必须返回 3 个工具,名称与
// manifest.tools 逐字一致(76 脚本构建期即核对该集合)。
func TestHandshakeThreeTools(t *testing.T) {
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
	want := []string{"rpm_summary", "rpm_unchanged", "rpm_verify"}
	if !slices.Equal(got, want) {
		t.Errorf("工具集 = %v\nwant %v", got, want)
	}
}

// TestToolsE2E 端到端跑 3 工具,验证返回 JSON 载荷结构稳定(允许空集 + note,
// 不依赖真实宿主 rpm DB)。真机无 rpm / 非 root 时应降级为 note 而非 panic。
func TestToolsE2E(t *testing.T) {
	sess, ctx, _ := connectSession(t)

	verifyText, isErr := callTool(t, sess, ctx, "rpm_verify", map[string]any{"package": "bash"})
	if isErr {
		t.Fatalf("rpm_verify(package=bash) 不应报错: %s", verifyText)
	}
	var verify VerifyResultPage
	if err := json.Unmarshal([]byte(verifyText), &verify); err != nil {
		t.Fatalf("rpm_verify 非 JSON: %v\n%s", err, verifyText)
	}
	if verify.Entries == nil {
		t.Fatalf("rpm_verify entries 应为 [] 而非 nil")
	}

	unchText, isErr := callTool(t, sess, ctx, "rpm_unchanged", map[string]any{"package": "bash"})
	if isErr {
		t.Fatalf("rpm_unchanged(package=bash) 不应报错: %s", unchText)
	}
	var unch UnchangedResult
	if err := json.Unmarshal([]byte(unchText), &unch); err != nil {
		t.Fatalf("rpm_unchanged 非 JSON: %v\n%s", err, unchText)
	}
	if unch.Packages == nil {
		t.Fatalf("rpm_unchanged packages 应为 [] 而非 nil")
	}

	sumText, isErr := callTool(t, sess, ctx, "rpm_summary", map[string]any{})
	if isErr {
		t.Fatalf("rpm_summary 不应报错: %s", sumText)
	}
	var sum SummaryResult
	if err := json.Unmarshal([]byte(sumText), &sum); err != nil {
		t.Fatalf("rpm_summary 非 JSON: %v\n%s", err, sumText)
	}
}

// TestRpmVerify_ValidationRejectedBySchema 参数非法时由 service.Validate 拒绝,
// 返回 isError=true 工具错误(不是 panic)。覆盖注入/遍历/互斥边界。
func TestRpmVerify_ValidationRejectedBySchema(t *testing.T) {
	sess, ctx, _ := connectSession(t)
	cases := []map[string]any{
		{"package": "bash; rm -rf /"},
		{"package": "--all"},
		{"package": ".."},
		{"package": "bash", "all": true},
		{"all": true, "limit": 0},
		{"all": true, "limit": 200000},
		{"all": true, "offset": -1},
	}
	for _, args := range cases {
		text, isErr := callTool(t, sess, ctx, "rpm_verify", args)
		if !isErr {
			t.Errorf("args %v 应返回 isError, got %q", args, truncateForLog(text))
		}
	}
}

// TestRpmUnchanged_ValidationRejectedBySchema unchanged 单包形态同样校验注入。
func TestRpmUnchanged_ValidationRejectedBySchema(t *testing.T) {
	sess, ctx, _ := connectSession(t)
	for _, args := range []map[string]any{
		{"package": "bash && rm"},
		{"package": "--nodeps"},
		{"limit": 0},
		{"offset": -5},
	} {
		text, isErr := callTool(t, sess, ctx, "rpm_unchanged", args)
		if !isErr {
			t.Errorf("args %v 应返回 isError, got %q", args, truncateForLog(text))
		}
	}
}

// --- helpers ---

// truncateForLog 限制日志输出长度,避免 dump 全部 JSON。
func truncateForLog(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
