// main_test.go 是 daedalus-search 的会话层测试:握手 / 工具名集合 / 端到端调
// 用 + 降级路径。数据源全部经 connect / run 注入,零触碰宿主 Baloo 与 D-Bus。
package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// testSession 装配内存内 MCP 会话,service 已带 connect=session 不可达 +
// 空结果 runner(handshake 阶段够用);E2E 用例自行注入 fakeDBus / fakeRunner。
func testSession(t *testing.T, configure func(*service)) (*mcp.ClientSession, context.Context, *service) {
	t.Helper()
	svc := &service{
		connect: func() (balooDBus, error) { return nil, errTestNoBus },
		run: func(_ context.Context, _ string, _ io.Reader, _ func([]byte) bool, _ ...string) error {
			return nil
		},
		binary:  "baloosearch-stub",
		timeout: searchTimeout,
	}
	if configure != nil {
		configure(svc)
	}
	server := newServer(svc)
	ct, st := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, st) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "search-test-client", Version: "0.0.0"}, nil)
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

// callJSON 调用工具,反序列化结果为 T。
func callJSON[T any](t *testing.T, s *mcp.ClientSession, ctx context.Context,
	tool string, args map[string]any) (T, bool) {
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
	var out T
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		t.Fatalf("%s 输出非 JSON: %v\n%s", tool, err, tc.Text)
	}
	return out, res.IsError
}

// callRaw 调用工具并返回原始 (text, isError)。用于 SDK schema 校验失败场景
// (返回非 JSON 错误文本)。
func callRaw(t *testing.T, s *mcp.ClientSession, ctx context.Context,
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

// TestHandshakeThreeTools 握手期 tools/list 必须返回三个工具,名称与
// manifest.tools 逐字一致。
func TestHandshakeThreeTools(t *testing.T) {
	sess, ctx, _ := testSession(t, nil)
	res, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	got := make([]string, 0, len(res.Tools))
	for _, tl := range res.Tools {
		got = append(got, tl.Name)
	}
	slices.Sort(got)
	want := []string{"search_content", "search_files", "search_reindex"}
	if !slices.Equal(got, want) {
		t.Errorf("工具集 = %v\nwant %v", got, want)
	}
	for _, tl := range res.Tools {
		if tl.Annotations == nil || !tl.Annotations.ReadOnlyHint {
			t.Errorf("%s 应标 ReadOnlyHint=true", tl.Name)
		}
		if tl.InputSchema == nil {
			t.Errorf("%s InputSchema 缺失", tl.Name)
		}
	}
}

// TestSearchFilesE2E_DBusUnavailable 端到端:connect 失败 → D-Bus advisory note,
// 仍尝试 baloosearch;测试用例默认 stub 无输出 → files=[] 但不报错。
func TestSearchFilesE2E_DBusUnavailable(t *testing.T) {
	sess, ctx, _ := testSession(t, nil)
	out, isErr := callJSON[map[string]any](t, sess, ctx, "search_files", map[string]any{"query": "anything"})
	if isErr {
		t.Errorf("不可达不应报错")
	}
	if _, ok := out["files"]; !ok {
		t.Errorf("应含 files 字段")
	}
	note, _ := out["note"].(string)
	if !strings.Contains(note, "D-Bus session bus 不可达") {
		t.Errorf("note = %q", note)
	}
}

// TestSearchFilesE2E_DBusUnavailableBalooSearchWorks 端到端 fallback:D-Bus
// 不可达但 baloosearch 能返回结果 → 应返回该结果(而非死等 D-Bus bail)。
func TestSearchFilesE2E_DBusUnavailableBalooSearchWorks(t *testing.T) {
	dir := t.TempDir()
	f := dir + "/hit.txt"
	_ = os.WriteFile(f, []byte("x"), 0o644)
	var balooCalls int
	sess, ctx, _ := testSession(t, func(s *service) {
		s.connect = func() (balooDBus, error) { return nil, errTestNoBus }
		s.run = func(_ context.Context, _ string, _ io.Reader, onLine func([]byte) bool, _ ...string) error {
			balooCalls++
			onLine([]byte(f))
			return nil
		}
	})
	out, isErr := callJSON[map[string]any](t, sess, ctx, "search_files", map[string]any{"query": "q"})
	if isErr {
		t.Errorf("fallback 不应报错")
	}
	if balooCalls != 1 {
		t.Errorf("baloosearch 应尝试 1 次: %d", balooCalls)
	}
	files, _ := out["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("应返回 1 条: %+v", out)
	}
	note, _ := out["note"].(string)
	if !strings.Contains(note, "D-Bus session bus 不可达") {
		t.Errorf("note 应含 D-Bus advisory: %q", note)
	}
}

// TestSearchFilesE2E_BalooNotRegistered D-Bus 上无 Baloo → note 提示 + 空集。
func TestSearchFilesE2E_BalooNotRegistered(t *testing.T) {
	sess, ctx, _ := testSession(t, func(s *service) {
		s.connect = func() (balooDBus, error) { return &fakeDBus{owned: false}, nil }
	})
	out, _ := callJSON[map[string]any](t, sess, ctx, "search_files", map[string]any{"query": "q"})
	note, _ := out["note"].(string)
	if !strings.Contains(note, "org.kde.baloo 未注册") {
		t.Errorf("note = %q", note)
	}
}

// TestSearchFilesE2E_NormalPath 全链路:fakeDBus 全绿 + fakeRunner 返回 1 行。
func TestSearchFilesE2E_NormalPath(t *testing.T) {
	dir := t.TempDir()
	f := dir + "/hit.txt"
	_ = os.WriteFile(f, []byte("x"), 0o644)
	sess, ctx, _ := testSession(t, func(s *service) {
		s.connect = func() (balooDBus, error) { return &fakeDBus{owned: true, indexing: true}, nil }
		fr := &fakeRunner{results: []fakeResult{{lines: lines(f)}}}
		s.run = fr.run
	})
	out, _ := callJSON[map[string]any](t, sess, ctx, "search_files", map[string]any{"query": "q"})
	files, _ := out["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("files = %+v", out)
	}
}

// TestSearchFilesE2E_ValidationErr 缺 query → schema 校验拒绝(isError=true)。
func TestSearchFilesE2E_ValidationErr(t *testing.T) {
	sess, ctx, _ := testSession(t, nil)
	if _, isErr := callRaw(t, sess, ctx, "search_files", map[string]any{}); !isErr {
		t.Errorf("缺 query 应报错")
	}
}

// TestSearchFilesE2E_NegativeSize size_min 负值 → schema 校验拒绝。
func TestSearchFilesE2E_NegativeSize(t *testing.T) {
	sess, ctx, _ := testSession(t, nil)
	if _, isErr := callRaw(t, sess, ctx, "search_files",
		map[string]any{"query": "q", "size_min": -1}); !isErr {
		t.Errorf("负 size_min 应报错")
	}
}

// TestSearchContentE2E_DBusUnavailable 端到端:content 同样降级。
func TestSearchContentE2E_DBusUnavailable(t *testing.T) {
	sess, ctx, _ := testSession(t, nil)
	out, isErr := callJSON[map[string]any](t, sess, ctx, "search_content", map[string]any{"query": "main"})
	if isErr {
		t.Errorf("不可达不应报错")
	}
	note, _ := out["note"].(string)
	if !strings.Contains(note, "D-Bus session bus 不可达") {
		t.Errorf("note = %q", note)
	}
}

// TestReindexE2E_L1Deferred 端到端:reindex 恒 started=false + note。
func TestReindexE2E_L1Deferred(t *testing.T) {
	sess, ctx, _ := testSession(t, nil)
	out, isErr := callJSON[map[string]any](t, sess, ctx, "search_reindex",
		map[string]any{"dir": "/home/u"})
	if isErr {
		t.Errorf("reindex 不应报错")
	}
	if started, _ := out["started"].(bool); started {
		t.Errorf("started 应 false")
	}
	note, _ := out["note"].(string)
	if !strings.Contains(note, "L1 deferred") {
		t.Errorf("note = %q", note)
	}
	if d, _ := out["dir"].(string); d != "/home/u" {
		t.Errorf("dir 应回显, got %q", d)
	}
}

// --- helper errors ---

// errTestNoBus 是 testSession 默认 connect 返回的 sentinel。
var errTestNoBus = &stringErr{"test: no session bus"}

// stringErr 用于 testSession 注入 connect 失败。
type stringErr struct{ s string }

func (e *stringErr) Error() string { return e.s }
