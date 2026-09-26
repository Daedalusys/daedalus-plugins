// trace 工具层端到端测试:内存 MCP 会话 + LogAudit 真实哈希链夹具
// (经 DAEDALUS_AUDIT_LOG_PATH env 注入,零触碰宿主 /var/log)。
// 钉握手工具集、四工具回包形态、游标续传闭环、tx 回放与错误面。
package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/audit"
)

// connectSession 建立内存内 MCP 会话(家族实证形态),结束时校验
// 会话与服务器均干净退出。
func connectSession(t *testing.T) (*mcp.ClientSession, context.Context) {
	t.Helper()
	server := newServer()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "trace-test-client", Version: "0.0.0"}, nil)
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

// callTrace 调用指定 trace 工具并返回 (结果, 首个文本块)。
func callTrace(t *testing.T, session *mcp.ClientSession, ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, string) {
	t.Helper()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("tools/call %s 传输失败: %v", name, err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("tools/call %s 无内容块", name)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("tools/call %s 回包非文本: %T", name, res.Content[0])
	}
	return res, text.Text
}

// fixtureLog 生成六行真实哈希链夹具(env 注入):两条 cli、两条 copilot
// (其一 denied)、tx-9 事务 begin+apply 两步;tx apply 步显式携带前一步
// entry_hash(与 daedalus-tx 发射端同法)。
func fixtureLog(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log := func(e audit.Entry) *audit.Record {
		e.LogPath = path
		if e.Args == nil {
			e.Args = audit.NewObject()
		}
		rec, err := audit.LogAudit(e)
		if err != nil {
			t.Fatalf("夹具 LogAudit 失败: %v", err)
		}
		return rec
	}
	log(audit.Entry{Identity: "cli", Tool: "fs.read_file", Outcome: "success"})
	log(audit.Entry{Identity: "cli", Tool: "shell_exec", Outcome: "error"})
	begin := log(audit.Entry{Identity: "daedalus-tx", Tool: "daedalus_tx_begin", TxID: "tx-9", TxStep: 0})
	log(audit.Entry{Identity: "daedalus-tx", Tool: "daedalus_tx_apply", TxID: "tx-9", TxStep: 1, TxPrevHash: begin.EntryHash})
	log(audit.Entry{Identity: "daedalus-copilot", Tool: "fs.write_file", Outcome: "denied"})
	log(audit.Entry{Identity: "daedalus-copilot", Tool: "fs.write_file", Outcome: "success"})
	t.Setenv(audit.EnvLogPath, path)
	return path
}

func TestNewServer_HandshakeFourTools(t *testing.T) {
	fixtureLog(t)
	if serverName != "daedalus-trace" {
		t.Errorf("serverName = %q, want %q", serverName, "daedalus-trace")
	}
	session, ctx := connectSession(t)
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	if len(res.Tools) != 4 {
		t.Fatalf("工具数 = %d, want 4", len(res.Tools))
	}
	names := []string{}
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	want := []string{"trace_session", "trace_summary", "trace_tool", "trace_tx"}
	if !slices.Equal(names, want) {
		t.Errorf("工具集 = %v, want %v", names, want)
	}
}

func TestTraceSession_HappyAndCursor(t *testing.T) {
	path := fixtureLog(t)
	session, ctx := connectSession(t)

	res, text := callTrace(t, session, ctx, "trace_session", map[string]any{"session_id": "daedalus-copilot"})
	if res.IsError {
		t.Fatalf("合法回放被误判为错误: %s", text)
	}
	var view sessionView
	if err := json.Unmarshal([]byte(text), &view); err != nil {
		t.Fatalf("回包非合法 JSON: %v\n%s", err, text)
	}
	if view.LogPath != path || view.SessionID != "daedalus-copilot" ||
		len(view.Entries) != 2 || view.NextCursor != 0 {
		t.Fatalf("回包漂移: %s", text)
	}
	for _, e := range view.Entries {
		if e.Identity != "daedalus-copilot" {
			t.Errorf("混入他人条目: %+v", e)
		}
	}
	if view.Entries[0].Outcome != "denied" || view.Entries[1].Outcome != "success" {
		t.Errorf("时间线序漂移: %+v", view.Entries)
	}
	// limit 截断 → next_cursor 续传闭环:fs.write_file 命中 line5/6,
	// limit=1 首轮回 cursor=5,续传取尽后 cursor 归零。
	res, text = callTrace(t, session, ctx, "trace_tool", map[string]any{"tool_name": "fs.write_file", "limit": 1})
	if res.IsError {
		t.Fatalf("limit 回放被误判为错误: %s", text)
	}
	var first toolView
	if err := json.Unmarshal([]byte(text), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Entries) != 1 || first.NextCursor != 5 || first.MatchedTotal != 2 {
		t.Fatalf("tool 视图截断态漂移: %s", text)
	}
	res, text = callTrace(t, session, ctx, "trace_tool", map[string]any{"tool_name": "fs.write_file", "cursor": 5})
	if res.IsError {
		t.Fatalf("游标续传被误判为错误: %s", text)
	}
	var second toolView
	if err := json.Unmarshal([]byte(text), &second); err != nil {
		t.Fatal(err)
	}
	if len(second.Entries) != 1 || second.Entries[0].LineNo != 6 || second.NextCursor != 0 {
		t.Fatalf("游标续传态漂移: %s", text)
	}
}

func TestTraceTx_HappyAndNotFound(t *testing.T) {
	fixtureLog(t)
	session, ctx := connectSession(t)

	res, text := callTrace(t, session, ctx, "trace_tx", map[string]any{"tx_id": "tx-9"})
	if res.IsError {
		t.Fatalf("tx 回放被误判为错误: %s", text)
	}
	var view txView
	if err := json.Unmarshal([]byte(text), &view); err != nil {
		t.Fatalf("回包非合法 JSON: %v\n%s", err, text)
	}
	if view.TxID != "tx-9" || view.StepCount != 2 || len(view.Entries) != 2 || !view.ChainValid {
		t.Fatalf("tx 回放漂移: %s", text)
	}
	// 创世点 = begin 步 tx_prev_hash(播种自最近非 tx 条目,非创世零值)。
	if view.Genesis == "" || view.Genesis == audit.GenesisHash {
		t.Errorf("tx 创世点应为前缀非 tx 条目哈希, got %q", view.Genesis)
	}
	res, text = callTrace(t, session, ctx, "trace_tx", map[string]any{"tx_id": "tx-nope"})
	if !res.IsError || !strings.Contains(text, "未找到") {
		t.Fatalf("不存在的 tx 未 fail-closed: (%v) %s", res.IsError, text)
	}
}

func TestTraceSummary_Stats(t *testing.T) {
	fixtureLog(t)
	session, ctx := connectSession(t)

	res, text := callTrace(t, session, ctx, "trace_summary", map[string]any{})
	if res.IsError {
		t.Fatalf("统计被误判为错误: %s", text)
	}
	var view summaryView
	if err := json.Unmarshal([]byte(text), &view); err != nil {
		t.Fatalf("回包非合法 JSON: %v\n%s", err, text)
	}
	if view.Total != 6 || view.ScannedLines != 6 || view.MalformedSkipped != 0 || view.TxCount != 1 {
		t.Fatalf("计数漂移: %+v", view)
	}
	if view.ByTool["fs.write_file"] != 2 || view.ByOutcome["denied"] != 1 ||
		view.ByOutcome["error"] != 1 || view.ByIdentity["daedalus-tx"] != 2 {
		t.Fatalf("分布漂移: %+v", view)
	}
	// 非 success = denied+error = 2/6。
	if view.FailureRate < 0.33 || view.FailureRate > 0.34 {
		t.Errorf("failure_rate = %v, want ≈1/3", view.FailureRate)
	}
}

func TestTraceTools_ErrorSurface(t *testing.T) {
	fixtureLog(t)
	session, ctx := connectSession(t)

	cases := []struct {
		tool string
		args map[string]any
	}{
		{"trace_session", map[string]any{"session_id": ""}},
		{"trace_session", map[string]any{"session_id": "cli", "since": "昨天"}},
		{"trace_session", map[string]any{"session_id": "cli", "limit": 0}},
		{"trace_session", map[string]any{"session_id": "cli", "limit": 501}},
		{"trace_session", map[string]any{"session_id": "cli", "cursor": -1}},
		{"trace_tool", map[string]any{"tool_name": ""}},
		{"trace_tx", map[string]any{"tx_id": "a\nb"}},
		{"trace_summary", map[string]any{"since": "2026-06-01T00:00:00Z", "until": "2026-01-01T00:00:00Z"}},
	}
	for _, tc := range cases {
		res, text := callTrace(t, session, ctx, tc.tool, tc.args)
		if !res.IsError {
			t.Errorf("%v 应被拒绝却成功: %s", tc.args, text)
		}
		if !strings.HasPrefix(text, "Error executing tool "+tc.tool+": ") {
			t.Errorf("错误文案形态漂移: %s", text)
		}
	}
	// env 指向不可读路径 → 数据源缺失显式报错(不返回空壳)。
	t.Setenv(audit.EnvLogPath, filepath.Join(t.TempDir(), "missing.jsonl"))
	res, text := callTrace(t, session, ctx, "trace_session", map[string]any{"session_id": "cli"})
	if !res.IsError || !strings.Contains(text, "不可读") {
		t.Fatalf("不可读日志未显式报错: (%v) %s", res.IsError, text)
	}
}
