// daedalus-fs 的行为测试:用 NewInMemoryTransports 做真实 MCP 握手,
// 断言 tools/list 与 ts 规格一致,并端到端验证 4 个工具的白名单语义。
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

	"github.com/Daedalusys/daedalus-sdk/pathguard"
	"github.com/Daedalusys/daedalus-sdk/policy"
)

// connectSession 按 cmd/daedalus-smoke 实证形态建立内存内客户端/服务器会话,
// 并在测试结束校验服务器随连接关闭而优雅退出。
func connectSession(t *testing.T) (*mcp.ClientSession, context.Context) {
	t.Helper()
	server := newServer()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "fs-test-client", Version: "0.0.0"}, nil)
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

// callToolText 调用工具并返回 (结果, 首个文本块内容)。
func callToolText(t *testing.T, session *mcp.ClientSession, ctx context.Context, tool string, args map[string]any) (*mcp.CallToolResult, string) {
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

// wantAnnotation 是 tools/list 注解断言的期望值(逐字对齐 fs_server.ts:224-297)。
type wantAnnotation struct {
	name        string
	description string
	readOnly    bool
	destructive bool
	idempotent  bool
	openWorld   bool
	required    []string
	properties  []string
}

// TestToolsList_MatchesDenoSpec 断言工具数量、名称、描述、注解与参数 schema。
func TestToolsList_MatchesDenoSpec(t *testing.T) {
	session, ctx := connectSession(t)
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	if len(res.Tools) != 4 {
		t.Fatalf("工具数量 = %d, want 4", len(res.Tools))
	}

	wants := []wantAnnotation{
		{
			name: "read_file", description: "Read text content from a file within allowed directories (/home, /var/log, /tmp).",
			readOnly: true, destructive: false, idempotent: true, openWorld: false,
			required: []string{"path"}, properties: []string{"path"},
		},
		{
			name: "write_file", description: "Write or overwrite text content to a file within allowed directories (/home, /var/log, /tmp). Automatically creates parent directories if they do not exist.",
			readOnly: false, destructive: true, idempotent: true, openWorld: false,
			required: []string{"path", "content"}, properties: []string{"content", "path"},
		},
		{
			name: "list_dir", description: "List contents of a directory within allowed directories (/home, /var/log, /tmp).",
			readOnly: true, destructive: false, idempotent: true, openWorld: false,
			required: []string{"path"}, properties: []string{"path"},
		},
		{
			name: "move_file", description: "Move or rename a file or directory within allowed directories (/home, /var/log, /tmp). Both source and destination must be strictly inside the allowed whitelist.",
			readOnly: false, destructive: true, idempotent: false, openWorld: false,
			required: []string{"src", "dst"}, properties: []string{"dst", "src"},
		},
	}

	byName := map[string]*mcp.Tool{}
	for _, tool := range res.Tools {
		byName[tool.Name] = tool
	}
	for _, want := range wants {
		tool, ok := byName[want.name]
		if !ok {
			t.Errorf("缺少工具 %q", want.name)
			continue
		}
		if tool.Description != want.description {
			t.Errorf("%s 描述漂移:\n got %q\nwant %q", want.name, tool.Description, want.description)
		}
		a := tool.Annotations
		if a == nil {
			t.Fatalf("%s 无 Annotations", want.name)
		}
		if a.ReadOnlyHint != want.readOnly {
			t.Errorf("%s readOnlyHint = %v, want %v", want.name, a.ReadOnlyHint, want.readOnly)
		}
		if a.DestructiveHint == nil || *a.DestructiveHint != want.destructive {
			t.Errorf("%s destructiveHint = %v, want %v", want.name, a.DestructiveHint, want.destructive)
		}
		if a.IdempotentHint != want.idempotent {
			t.Errorf("%s idempotentHint = %v, want %v", want.name, a.IdempotentHint, want.idempotent)
		}
		if a.OpenWorldHint == nil || *a.OpenWorldHint != want.openWorld {
			t.Errorf("%s openWorldHint = %v, want %v", want.name, a.OpenWorldHint, want.openWorld)
		}

		schema, ok := tool.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("%s inputSchema 类型异常: %T", want.name, tool.InputSchema)
		}
		wantRequired := slices.Clone(want.required)
		slices.Sort(wantRequired)
		if got := schemaStringSlice(schema, "required"); !slices.Equal(got, wantRequired) {
			t.Errorf("%s required = %v, want %v", want.name, got, wantRequired)
		}
		props, ok := schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s properties 缺失: %v", want.name, schema["properties"])
		}
		names := make([]string, 0, len(props))
		for k := range props {
			names = append(names, k)
		}
		slices.Sort(names)
		if !slices.Equal(names, want.properties) {
			t.Errorf("%s properties = %v, want %v", want.name, names, want.properties)
		}
	}
}

// schemaStringSlice 提取 JSON Schema map 中某字符串数组字段(如 required)。
func schemaStringSlice(schema map[string]any, key string) []string {
	raw, ok := schema[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

func TestReadFile_InsideAllowlist(t *testing.T) {
	session, ctx := connectSession(t)
	base := mustTempDir(t)
	file := filepath.Join(base, "hello.txt")
	if err := os.WriteFile(file, []byte("hello daedalus"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, text := callToolText(t, session, ctx, "read_file", map[string]any{"path": file})
	if res.IsError {
		t.Fatalf("read_file 白名单内文件失败: %s", text)
	}
	if text != "hello daedalus" {
		t.Errorf("内容 = %q, want %q", text, "hello daedalus")
	}
}

func TestReadFile_OutsideAllowlist(t *testing.T) {
	session, ctx := connectSession(t)
	res, text := callToolText(t, session, ctx, "read_file", map[string]any{"path": "/etc/shadow"})
	if !res.IsError {
		t.Fatalf("/etc/shadow 竟然读取成功: %q", text)
	}
	if !strings.HasPrefix(text, "Error: ") || !strings.Contains(text, "outside allowed directories") {
		t.Errorf("错误形态漂移(应 Error: 前缀 + outside): %q", text)
	}
}

func TestReadFile_SymlinkEscape(t *testing.T) {
	session, ctx := connectSession(t)
	base := mustTempDir(t)
	link := filepath.Join(base, "escape")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}
	res, text := callToolText(t, session, ctx, "read_file", map[string]any{"path": filepath.Join(link, "passwd")})
	if !res.IsError || !strings.Contains(text, "outside allowed directories") {
		t.Errorf("symlink 逃逸未被拦截: isError=%v text=%q", res.IsError, text)
	}
}

func TestReadFile_DirectoryTarget(t *testing.T) {
	session, ctx := connectSession(t)
	base := mustTempDir(t)
	res, text := callToolText(t, session, ctx, "read_file", map[string]any{"path": base})
	if !res.IsError || !strings.Contains(text, "Target is a directory, not a file") {
		t.Errorf("目录目标错误形态漂移: isError=%v text=%q", res.IsError, text)
	}
}

// TestWriteFile_MkdirListMove 覆盖 write_file 建父目录、UTF-16 计数、
// list_dir 的 JSON 数组形态与排序、move_file 的完整闭环。
func TestWriteFile_MkdirListMove(t *testing.T) {
	session, ctx := connectSession(t)
	base := mustTempDir(t)

	nested := filepath.Join(base, "sub", "deep", "a.txt")
	res, text := callToolText(t, session, ctx, "write_file", map[string]any{"path": nested, "content": "abc"})
	if res.IsError {
		t.Fatalf("write_file 失败: %s", text)
	}
	if want := fmt.Sprintf("Successfully wrote 3 characters to %s", nested); text != want {
		t.Errorf("write 消息 = %q, want %q", text, want)
	}

	// 非 BMP 字符占 2 个 UTF-16 码元(ts content.length 语义):🙂=2 + "ab"=2 → 4。
	emoji := filepath.Join(base, "b.txt")
	_, text = callToolText(t, session, ctx, "write_file", map[string]any{"path": emoji, "content": "🙂ab"})
	if want := fmt.Sprintf("Successfully wrote 4 characters to %s", emoji); text != want {
		t.Errorf("UTF-16 计数消息 = %q, want %q", text, want)
	}

	res, text = callToolText(t, session, ctx, "list_dir", map[string]any{"path": filepath.Join(base, "sub", "deep")})
	if res.IsError {
		t.Fatalf("list_dir 失败: %s", text)
	}
	var wantJSON, gotJSON []byte
	wantJSON, _ = json.MarshalIndent([]string{"a.txt"}, "", "  ")
	gotJSON = []byte(text)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("list_dir 输出 = %q, want %q", text, wantJSON)
	}

	dst := filepath.Join(base, "moved.txt")
	res, text = callToolText(t, session, ctx, "move_file", map[string]any{"src": nested, "dst": dst})
	if res.IsError {
		t.Fatalf("move_file 失败: %s", text)
	}
	if want := fmt.Sprintf("Successfully moved %s to %s", nested, dst); text != want {
		t.Errorf("move 消息 = %q, want %q", text, want)
	}
	if _, err := os.Stat(nested); !os.IsNotExist(err) {
		t.Errorf("源文件仍存在: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil || string(data) != "abc" {
		t.Errorf("目标文件内容异常: %q, %v", data, err)
	}
}

func TestWriteFile_RejectedOutside(t *testing.T) {
	session, ctx := connectSession(t)
	res, text := callToolText(t, session, ctx, "write_file", map[string]any{"path": "/etc/daedalus_evil", "content": "x"})
	if !res.IsError || !strings.Contains(text, "outside allowed directories") {
		t.Errorf("越界写入未被拦截: isError=%v text=%q", res.IsError, text)
	}
	if _, err := os.Stat("/etc/daedalus_evil"); !os.IsNotExist(err) {
		t.Error("/etc 下出现了不应存在的文件")
	}
}

// TestNullByteAndMissingArgs 覆盖畸形输入:null 字节路径与缺失必填参数。
func TestNullByteAndMissingArgs(t *testing.T) {
	session, ctx := connectSession(t)

	res, text := callToolText(t, session, ctx, "read_file", map[string]any{"path": "/tmp/a\x00b"})
	if !res.IsError || !strings.Contains(text, "null bytes are forbidden") {
		t.Errorf("null 字节未被拦截: isError=%v text=%q", res.IsError, text)
	}

	// 缺失 required=path:SDK schema 校验层拦截,同样以 isError 结果返回。
	res, text = callToolText(t, session, ctx, "read_file", map[string]any{})
	if !res.IsError {
		t.Errorf("缺失 path 竟然成功: %q", text)
	}
	if !strings.Contains(text, "path") {
		t.Errorf("缺失参数错误消息未提及 path: %q", text)
	}
}

// mustTempDir 在 fs 白名单目录 /tmp 下创建隔离临时目录并注册清理。
func mustTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "daedalus-fs-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("解析临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(real) })
	return real
}

// —— policy.toml 单一事实源接线测试(计划 todo 12)——
// 经 DAEDALUS_POLICY_PATH 指向 testdata 后调用 applyPolicy,
// 断言 [fs].allowed_dirs 逐字进入 pathguard 并在真实 MCP 往返中生效。

// TestPolicyInjection_FollowsPolicyToml 证明策略注入端到端生效:
// testdata 把白名单收缩为仅 /tmp 后,/tmp 放行、/var/log 与 /etc 被拒,
// 且拒绝消息回显的是策略白名单(证明校验器读的是注入值而非常量)。
func TestPolicyInjection_FollowsPolicyToml(t *testing.T) {
	orig := slices.Clone(pathguard.AllowedDirs)
	t.Cleanup(func() { pathguard.WithAllowedDirs(orig) })

	t.Setenv(policy.EnvPolicyPath, filepath.Join("testdata", "policy.toml"))
	if err := applyPolicy(); err != nil {
		t.Fatalf("applyPolicy 加载 testdata 策略失败: %v", err)
	}
	if !slices.Equal(pathguard.AllowedDirs, []string{"/tmp"}) {
		t.Fatalf("allowed_dirs 未注入: %v", pathguard.AllowedDirs)
	}

	session, ctx := connectSession(t)
	base := mustTempDir(t)
	file := filepath.Join(base, "p.txt")
	if res, text := callToolText(t, session, ctx, "write_file", map[string]any{"path": file, "content": "ok"}); res.IsError {
		t.Fatalf("注入 /tmp-only 后写 /tmp 应放行: %s", text)
	}

	res, text := callToolText(t, session, ctx, "list_dir", map[string]any{"path": "/var/log"})
	if !res.IsError || !strings.Contains(text, "outside allowed directories") {
		t.Fatalf("注入 /tmp-only 后 /var/log 应被拒: isError=%v text=%q", res.IsError, text)
	}
	// 拒绝消息的白名单回显必须来自注入值(现状默认回显含 /home、/var/log)。
	if !strings.Contains(text, "outside allowed directories (/tmp)") {
		t.Errorf("拒绝消息未回显策略白名单 /tmp: %q", text)
	}
	if strings.Contains(text, "/home") {
		t.Errorf("拒绝消息仍含未注入的默认目录(校验器读了常量而非策略): %q", text)
	}
}

// TestPolicyInjection_CorruptRefusesStartup 钉死 fail-closed:
// 损坏 TOML → applyPolicy 报错(main 据此拒绝启动)。
func TestPolicyInjection_CorruptRefusesStartup(t *testing.T) {
	t.Setenv(policy.EnvPolicyPath, filepath.Join("testdata", "corrupt.toml"))
	if err := applyPolicy(); err == nil {
		t.Fatal("损坏策略竟然加载成功(应拒绝启动)")
	}
}

// TestPolicyInjection_MissingFallsBackToDefault 钉死稳健性要求:
// 显式指向缺失 = 硬错误(不静默降级);整体缺失 = Default 回退、
// pathguard 白名单保持现状 3 目录、applyPolicy 零错误(服务器可启动)。
func TestPolicyInjection_MissingFallsBackToDefault(t *testing.T) {
	orig := slices.Clone(pathguard.AllowedDirs)
	t.Cleanup(func() { pathguard.WithAllowedDirs(orig) })

	t.Setenv(policy.EnvPolicyPath, filepath.Join(t.TempDir(), "absent.toml"))
	if err := applyPolicy(); err == nil {
		t.Fatal("显式指向缺失应报错(不得静默回退)")
	}

	t.Setenv(policy.EnvPolicyPath, "")
	if _, err := os.Stat(policy.ProductionPath); err == nil {
		t.Skip("本机存在生产策略,跳过缺失回退演练")
	}
	t.Chdir(t.TempDir()) // 空目录上溯不可能命中仓库回溯路径。
	if err := applyPolicy(); err != nil {
		t.Fatalf("全缺失应回退 Default 并成功: %v", err)
	}
	if !slices.Equal(pathguard.AllowedDirs, []string{"/home", "/var/log", "/tmp"}) {
		t.Errorf("Default 回退后白名单异常: %v", pathguard.AllowedDirs)
	}
}
