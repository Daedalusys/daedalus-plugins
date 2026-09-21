// daedalus-pkg 的行为测试:内存内 MCP 往返断言 tools/list 的
// 名称/描述/schema/注解与 py 版一致,并端到端验证注入式命令执行下
// 的包名注入拒绝、回退链与 JSON 文本序列化。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/pkgquery"
)

// fakeStep/scriptedRunner 提供与 internal 包测试同型的脚本化命令替身。
type fakeStep struct {
	stdout, stderr string
	code           int
	err            error
}

type scriptedRunner struct {
	calls [][]string
	steps []fakeStep
	idx   int
}

func (r *scriptedRunner) run(_ context.Context, name string, args []string) (string, string, int, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	s := r.steps[r.idx]
	if r.idx < len(r.steps)-1 {
		r.idx++
	}
	return s.stdout, s.stderr, s.code, r.errOf(s)
}

func (r *scriptedRunner) errOf(s fakeStep) error { return s.err }

// connectSession 按 cmd/daedalus-smoke 实证形态建立内存内客户端/服务器会话。
func connectSession(t *testing.T, svc *pkgquery.Service) (*mcp.ClientSession, context.Context) {
	t.Helper()
	server := newServer(svc)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "pkg-test-client", Version: "0.0.0"}, nil)
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
func callToolText(t *testing.T, session *mcp.ClientSession, ctx context.Context, tool string, args any) (*mcp.CallToolResult, string) {
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

// TestToolsList_MatchesPySpec 断言两个工具的名称、描述、schema 与注解
// 与 pkg_server.py 逐字一致(名称=函数名,描述=docstring,default="*")。
func TestToolsList_MatchesPySpec(t *testing.T) {
	session, ctx := connectSession(t, pkgquery.NewService(nil))
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	if len(res.Tools) != 2 {
		t.Fatalf("工具数量 = %d, want 2", len(res.Tools))
	}

	byName := map[string]*mcp.Tool{}
	for _, tool := range res.Tools {
		byName[tool.Name] = tool
	}

	for _, name := range []string{"dnf_query", "dnf_list_installed"} {
		tool, ok := byName[name]
		if !ok {
			t.Fatalf("缺少工具 %q(与 py 函数名同名是硬要求)", name)
			continue
		}
		a := tool.Annotations
		if a == nil || !a.ReadOnlyHint {
			t.Errorf("%s 注解缺失或非只读: %+v", name, a)
		}
		if a != nil && (a.DestructiveHint == nil || *a.DestructiveHint != false) {
			t.Errorf("%s destructiveHint 应为显式 false: %+v", name, a.DestructiveHint)
		}
	}

	q, _ := byName["dnf_query"].InputSchema.(map[string]any)
	if got := schemaStrings(q, "required"); !slices.Equal(got, []string{"name"}) {
		t.Errorf("dnf_query required = %v, want [name]", got)
	}
	if props, ok := q["properties"].(map[string]any); !ok || len(props) != 1 {
		t.Errorf("dnf_query properties = %v, want 仅 name", q["properties"])
	}

	l, _ := byName["dnf_list_installed"].InputSchema.(map[string]any)
	if got := schemaStrings(l, "required"); len(got) != 0 {
		t.Errorf("dnf_list_installed required = %v, want 空(pattern 有默认值)", got)
	}
	props, ok := l["properties"].(map[string]any)
	if !ok {
		t.Fatalf("dnf_list_installed properties 缺失: %v", l["properties"])
	}
	pat, ok := props["pattern"].(map[string]any)
	if !ok {
		t.Fatalf("pattern 属性缺失: %v", props)
	}
	if pat["type"] != "string" {
		t.Errorf("pattern type = %v, want string", pat["type"])
	}
	// py:72 默认参数 pattern="*" 必须出现在 schema default。
	if pat["default"] != "*" {
		t.Errorf("pattern default = %v, want %q", pat["default"], "*")
	}
	// 描述含 py docstring 的关键中文句(全量对照见证据文件对照表)。
	if !strings.Contains(byName["dnf_list_installed"].Description, "列出匹配模式的已安装软件包（只读）。") {
		t.Errorf("dnf_list_installed 描述漂移: %q", byName["dnf_list_installed"].Description)
	}
	if !strings.Contains(byName["dnf_query"].Description, "查询给定软件包名称的软件包信息（只读）。") {
		t.Errorf("dnf_query 描述漂移: %q", byName["dnf_query"].Description)
	}
}

// schemaStrings 提取 schema map 里的字符串数组字段(如 required)。
func schemaStrings(schema map[string]any, key string) []string {
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

// TestDnfQuery_EndToEnd_FallbackChain 端到端验证 rpm 未命中 → dnf 回退。
func TestDnfQuery_EndToEnd_FallbackChain(t *testing.T) {
	r := &scriptedRunner{steps: []fakeStep{
		{code: 1, stderr: "package bash-doc not installed"},
		{stdout: "bash-doc-5.2.15-5.el9.noarch\n", code: 0},
	}}
	session, ctx := connectSession(t, pkgquery.NewService(r.run))
	res, text := callToolText(t, session, ctx, "dnf_query", map[string]any{"name": "bash-doc"})
	if res.IsError {
		t.Fatalf("回退链失败: %s", text)
	}
	if want := "bash-doc-5.2.15-5.el9.noarch"; text != want {
		t.Errorf("结果 = %q, want %q", text, want)
	}
	want := [][]string{{"rpm", "-q", "--info", "bash-doc"}, {"dnf", "repoquery", "--info", "bash-doc"}}
	if !slices.EqualFunc(r.calls, want, slices.Equal) {
		t.Errorf("调用序列 = %v, want %v", r.calls, want)
	}
}

// TestMalformedInput_Rejections 对抗性输入:注入包名、空参数、类型错乱
// 全部以 isError 拦截,且不得触碰任何外部命令。
func TestMalformedInput_Rejections(t *testing.T) {
	r := &scriptedRunner{steps: []fakeStep{{stdout: "should never run", code: 0}}}
	session, ctx := connectSession(t, pkgquery.NewService(r.run))

	cases := []struct {
		tool, args, wantSub string
	}{
		{"dnf_query", `{"name":";rm -rf"}`, "Invalid package name or pattern: ;rm -rf"},
		{"dnf_query", `{"name":""}`, "Package name/pattern cannot be empty."},
		{"dnf_list_installed", `{"pattern":"$(curl evil)"}`, "Invalid package name or pattern: $(curl evil)"},
		{"dnf_list_installed", `{"pattern":"   "}`, "Package name/pattern cannot be empty."},
		{"dnf_query", `{}`, "name"}, // required 缺失由 schema 层拦截
	}
	for _, tc := range cases {
		var args map[string]any
		if tc.args != `{}` {
			if err := json.Unmarshal([]byte(tc.args), &args); err != nil {
				t.Fatal(err)
			}
		} else {
			args = map[string]any{}
		}
		res, text := callToolText(t, session, ctx, tc.tool, args)
		if !res.IsError {
			t.Errorf("%s(%s) 竟然成功: %q", tc.tool, tc.args, text)
		}
		if !strings.Contains(text, tc.wantSub) {
			t.Errorf("%s(%s) 错误串 = %q, want 含 %q", tc.tool, tc.args, text, tc.wantSub)
		}
	}
	if len(r.calls) != 0 {
		t.Errorf("畸形输入触发了外部命令: %v", r.calls)
	}
}

// TestDnfQuery_NonStringArgRejected 深嵌套/类型错乱的 name(对象)被 schema 拦截。
func TestDnfQuery_NonStringArgRejected(t *testing.T) {
	r := &scriptedRunner{steps: []fakeStep{{}}}
	session, ctx := connectSession(t, pkgquery.NewService(r.run))
	res, text := callToolText(t, session, ctx, "dnf_query", map[string]any{"name": map[string]any{"deep": []any{1, 2}}})
	if !res.IsError {
		t.Errorf("对象型 name 竟然成功: %q", text)
	}
}

// TestDnfListInstalled_JSONTextShape 断言列表结果以 indent=2 JSON 文本呈现
// (对应 FastMCP 对非字符串返回值 json.dumps(..., indent=2))。
func TestDnfListInstalled_JSONTextShape(t *testing.T) {
	r := &scriptedRunner{steps: []fakeStep{{stdout: "zsh-1\nbash-2\n", code: 0}}}
	session, ctx := connectSession(t, pkgquery.NewService(r.run))
	res, text := callToolText(t, session, ctx, "dnf_list_installed", nil) // 未提供 pattern → 默认 "*"
	if res.IsError {
		t.Fatalf("调用失败: %s", text)
	}
	if want := "[\n  \"bash-2\",\n  \"zsh-1\"\n]"; text != want {
		t.Errorf("JSON 文本形态 = %q, want %q", text, want)
	}
	if !slices.Equal(r.calls[0], []string{"rpm", "-qa", "*"}) {
		t.Errorf("默认 pattern 未生效: %v", r.calls[0])
	}
}

// TestDnfListInstalled_SpawnErrorSingleElement 无 rpm 的宿主上错误以
// 单元素列表返回(py:102 形态),而非 MCP 异常。
func TestDnfListInstalled_SpawnErrorSingleElement(t *testing.T) {
	r := &scriptedRunner{steps: []fakeStep{{err: errors.New(`exec: "rpm": executable file not found in $PATH`)}}}
	session, ctx := connectSession(t, pkgquery.NewService(r.run))
	res, text := callToolText(t, session, ctx, "dnf_list_installed", map[string]any{"pattern": "bash*"})
	if res.IsError {
		t.Fatalf("py 版此路径返回数据而非异常,Go 不应标 isError: %s", text)
	}
	var got []string
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("回包不是合法 JSON: %v (%q)", err, text)
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], "Error executing rpm -qa: ") {
		t.Errorf("回包 = %v, want 单元素 Error executing rpm -qa 前缀", got)
	}
}
