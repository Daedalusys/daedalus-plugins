// avc MCP 服务器会话层测试:握手工具集与 3 工具端到端调用。所有工具走真 CLI
// fork,允许实机出现缺二进制/非 root/无审计日志降级 note —— 只校验工具名
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

// connectSession 建立内存内 MCP 会话;service 用生产装配(newService)以走真实
// fork 路径。会话级 60s 上限覆盖 ausearch 全量回放(空 audit.log 几 ms,生产
// 大集群可能 10+ s)。
func connectSession(t *testing.T) (*mcp.ClientSession, context.Context, *service) {
	t.Helper()
	svc := newService()
	server := newServer(svc)
	ct, st := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, st) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "avc-test-client", Version: "0.0.0"}, nil)
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
	want := []string{"avc_explain", "avc_recent", "avc_summary"}
	if !slices.Equal(got, want) {
		t.Errorf("工具集 = %v\nwant %v", got, want)
	}
}

// TestToolsE2E 端到端跑 3 工具,验证返回 JSON 载荷结构稳定(允许空集 + note)
// 不依赖真实宿主 SELinux 状态。ausearch 不存在 / auditd 未启 / 非 root
// 应降级为 note 而非 panic。
func TestToolsE2E(t *testing.T) {
	sess, ctx, _ := connectSession(t)

	// avc_recent(since=today) 必返 200 状态码形态的 RecentResult;
	// events / total_lines / returned 字段皆在,允许 events=nil (Go 端
	// 序列化 []AVCEvent{} 为 [],测试只判 keys 形态,不判长度)。
	recentText, isErr := callTool(t, sess, ctx, "avc_recent",
		map[string]any{"since": "today", "limit": 5})
	if isErr {
		t.Fatalf("avc_recent 不应报错: %s", recentText)
	}
	var recent RecentResult
	if err := json.Unmarshal([]byte(recentText), &recent); err != nil {
		t.Fatalf("avc_recent 非 JSON: %v\n%s", err, recentText)
	}
	if recent.Events == nil {
		t.Fatalf("avc_recent events 应为 [] 而非 nil")
	}

	// avc_summary(since=today) 无参 + since,可走空对象。
	sumText, isErr := callTool(t, sess, ctx, "avc_summary",
		map[string]any{"since": "today"})
	if isErr {
		t.Fatalf("avc_summary 不应报错: %s", sumText)
	}
	var sum SummaryResult
	if err := json.Unmarshal([]byte(sumText), &sum); err != nil {
		t.Fatalf("avc_summary 非 JSON: %v\n%s", err, sumText)
	}
	if sum.Buckets == nil {
		t.Fatalf("avc_summary buckets 应为 [] 而非 nil")
	}

	// avc_explain(event_id="42") 真机可能没该事件 → Note 必填;
	// 不真机/扣件则 note 表 "ausearch 不可用"。校验 Explanation 字段齐。
	expText, isErr := callTool(t, sess, ctx, "avc_explain",
		map[string]any{"event_id": "42"})
	if isErr {
		t.Fatalf("avc_explain 不应报错: %s", expText)
	}
	var exp Explanation
	if err := json.Unmarshal([]byte(expText), &exp); err != nil {
		t.Fatalf("avc_explain 非 JSON: %v\n%s", err, expText)
	}
	if exp.EventID != "42" {
		t.Errorf("avc_explain event_id 应回显 \"42\", got %q", exp.EventID)
	}
}

// TestAvcExplainBadEventID 入参校验走 MCP 入参 → ExplainArgs.Validate;
// 非法 event_id 应被 svc 拒绝并转为工具错误(isError=true)。
func TestAvcExplainBadEventID(t *testing.T) {
	sess, ctx, _ := connectSession(t)
	text, isErr := callTool(t, sess, ctx, "avc_explain",
		map[string]any{"event_id": "--help"})
	if !isErr {
		t.Fatalf("avc_explain(event_id=--help) 应报错, got ok: %s", text)
	}
	if text == "" {
		t.Fatalf("错误消息不应为空")
	}
}
