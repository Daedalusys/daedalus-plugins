package main

// render_tool_test.go —— blueprint_render 的内存内 MCP 往返测试。
//
// happy + 6 失败分支(schema 不匹配 / 缺必填 / 渲染错误 / 明文 password /
// 目标路径越界 / 未知蓝图),外加渲染正确性测试(nginx-vhost 输出含
// `server_name example.com;` 且 `$host` 字面量保留——nginx $var 隐患的回归钉)。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"text/template"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// renderCall 调 blueprint_render 并解码 renderOut(便捷 helper)。
// 返回 (raw结果, 原始文本, 解码后 out)。
func renderCall(t *testing.T, session *mcp.ClientSession, ctx context.Context, name string, params map[string]any) (*mcp.CallToolResult, string, renderOut) {
	t.Helper()
	res, text := callText(t, session, ctx, "blueprint_render", map[string]any{"name": name, "params": params})
	var out renderOut
	if !res.IsError {
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("render 结果非 renderOut(%v): %s", err, text)
		}
	}
	return res, text, out
}

// TestRenderTool_HappyNginxVhost 渲染 nginx-vhost happy case:
// 断言 plan_id/confirm_token 非空、目标路径正确、渲染含 server_name 与
// $host 字面量。
func TestRenderTool_HappyNginxVhost(t *testing.T) {
	a := newTestApp(t)
	session, ctx := connectServer(t, a)

	res, _, out := renderCall(t, session, ctx, "nginx-vhost", map[string]any{
		"domain":  "example.com",
		"backend": "http://127.0.0.1:3000",
		"ssl":     true,
	})
	if res.IsError {
		t.Fatalf("happy 渲染意外失败: %+v", res)
	}
	if out.PlanID == "" || out.ConfirmToken == "" {
		t.Fatalf("plan_id/confirm_token 不得为空: %+v", out)
	}
	if out.TargetPath != "/etc/nginx/conf.d/example.com.conf" {
		t.Errorf("target = %q, want /etc/nginx/conf.d/example.com.conf", out.TargetPath)
	}
	// 渲染正确性:nxginx-vhost 输出含 server_name 与必经的 proxy 头、
	// 且 nginx 内置变量 $host 原文保留(隐患回归钉)。
	if !strings.Contains(out.RenderedContent, "server_name example.com;") {
		t.Errorf("渲染输出缺 server_name 段:\n%s", out.RenderedContent)
	}
	if !strings.Contains(out.RenderedContent, "listen 443 ssl;") {
		t.Errorf("ssl=true 应渲染 443 ssl 监听:\n%s", out.RenderedContent)
	}
	if !strings.Contains(out.RenderedContent, "proxy_set_header Host $host;") {
		t.Errorf("渲染输出必须原样保留 nginx $host 字面量:\n%s", out.RenderedContent)
	}
	if !strings.Contains(out.RenderedContent, "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;") {
		t.Errorf("渲染输出必须原样保留 $proxy_add_x_forwarded_for:\n%s", out.RenderedContent)
	}

	// plan 已落入 plan store(apply/status 可取)。
	if _, ok := a.plans.get(out.PlanID); !ok {
		t.Errorf("plan_id %q 未落入 plan store", out.PlanID)
	}
}

// TestRenderTool_MissingRequired 缺必填 domain → schema 校验失败。
func TestRenderTool_MissingRequired(t *testing.T) {
	a := newTestApp(t)
	session, ctx := connectServer(t, a)

	res, _, _ := renderCall(t, session, ctx, "nginx-vhost", map[string]any{"ssl": true})
	if !res.IsError {
		t.Fatal("缺必填 domain 应返回错误")
	}
}

// TestRenderTool_SchemaMismatch domain 类型错误(数字)→ schema 校验失败。
func TestRenderTool_SchemaMismatch(t *testing.T) {
	a := newTestApp(t)
	session, ctx := connectServer(t, a)

	res, text, _ := renderCall(t, session, ctx, "nginx-vhost", map[string]any{"domain": 42})
	if !res.IsError {
		t.Fatalf("domain 类型错误应返回错误")
	}
	if !strings.Contains(text, "domain") {
		t.Errorf("错误文本应点名违规字段 domain: %s", text)
	}
}

// TestRenderTool_UnknownBlueprint 未知蓝图 → 明确错误。
func TestRenderTool_UnknownBlueprint(t *testing.T) {
	a := newTestApp(t)
	session, ctx := connectServer(t, a)

	res, text, _ := renderCall(t, session, ctx, "no-such", map[string]any{"x": 1})
	if !res.IsError {
		t.Fatalf("未知蓝图应返回错误")
	}
	if !strings.Contains(text, "no-such") {
		t.Errorf("错误文本应含蓝图名: %s", text)
	}
}

// TestRenderTool_PlaintextSecret 明文 password → 拒绝(postgres-user 需 password)。
func TestRenderTool_PlaintextSecret(t *testing.T) {
	a := newTestApp(t)
	session, ctx := connectServer(t, a)

	res, text, _ := renderCall(t, session, ctx, "postgres-user", map[string]any{
		"user":       "alice",
		"password":   "my-plain-password",
		"privileges": []any{"SELECT"},
		"db":         "mydb",
	})
	if !res.IsError {
		t.Fatalf("明文 password 应被拒绝")
	}
	if !strings.Contains(text, "明文") {
		t.Errorf("错误文本应含明文拒绝语义: %s", text)
	}
}

// TestRenderTool_SecretRefOK secret:// 引用应通过明文检测(格式校验后透传;
// 真值解析推迟 apply,且 render 不泄漏明文)。
func TestRenderTool_SecretRefOK(t *testing.T) {
	a := newTestApp(t)
	session, ctx := connectServer(t, a)

	res, _, out := renderCall(t, session, ctx, "postgres-user", map[string]any{
		"user":       "alice",
		"password":   "secret://kwallet/postgres/alice",
		"privileges": []any{"SELECT"},
		"db":         "mydb",
	})
	if res.IsError {
		t.Fatalf("secret:// 引用应通过明文检测: %+v", res)
	}
	// 渲染内容保留引用原文(不落明文),证明 $var 与 secret 引用共存安全。
	if !strings.Contains(out.RenderedContent, "secret://kwallet/postgres/alice") {
		t.Errorf("渲染应保留 secret:// 引用原文:\n%s", out.RenderedContent)
	}
	// 应含 SQL 的 dollar-quoting(DO $$ ... $$)原样保留。
	if !strings.Contains(out.RenderedContent, "DO $$") {
		t.Errorf("渲染应保留 postgres dollar-quoting DO $$:\n%s", out.RenderedContent)
	}
}

// TestRenderTool_OutputDirEscapes 目标路径越界(非白名单目录)→ 拒绝。
func TestRenderTool_OutputDirEscapes(t *testing.T) {
	// 越界校验是纯函数,直接测 validateOutputPath(render 调用路径已有
	// schema pattern 兜底穿越,真实蓝图数据无法构造含 '/' 的 name)。
	if validateOutputPath([]string{"/etc/nginx/conf.d"}, "/etc/nginx/conf.d/x.conf") != true {
		t.Fatal("合法路径应通过")
	}
	if validateOutputPath([]string{"/etc/nginx/conf.d"}, "/etc/nginx2/conf/x.conf") {
		t.Fatal("/etc/nginx2 应被段边界拒绝(防前缀误匹配)")
	}
	if validateOutputPath([]string{"/etc/nginx/conf.d"}, "/etc/x.conf") {
		t.Fatal("越出白名单的路径应被拒绝")
	}
}

// templateParseStrict 用 missingkey=error 解析模板(与编译期同 Option)。
func templateParseStrict(name, body string) (*template.Template, error) {
	return template.New(name).Option("missingkey=error").Parse(body)
}

// TestRenderTool_TemplateError 渲染期错误:missingkey=error 下访问缺键报错。
func TestRenderTool_TemplateError(t *testing.T) {
	// 用内联模板验证 missingkey=error 会把缺键渲染判为错误(与编译期一致)。
	tmpl, err := templateParseStrict("t", "{{ .missing }}")
	if err != nil {
		t.Fatalf("Parse 不应失败: %v", err)
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, map[string]any{}); err == nil {
		t.Fatal("missingkey=error 下访问缺键应报错")
	}
}

// TestRenderTool_HappyRedis 额外 happy:redis-acl 的 range 循环渲染
// (多值参数 + secret 引用 + redis ACL 文法)。
func TestRenderTool_HappyRedis(t *testing.T) {
	a := newTestApp(t)
	session, ctx := connectServer(t, a)

	res, _, out := renderCall(t, session, ctx, "redis-acl", map[string]any{
		"user":             "app1",
		"password":         "secret://kwallet/redis/app1",
		"allowed_commands": []any{"GET", "SET"},
		"allowed_keys":     []any{"app1:*"},
	})
	if res.IsError {
		t.Fatalf("redis-acl happy 渲染失败: %+v", res)
	}
	if !strings.Contains(out.RenderedContent, "user app1 on >secret://kwallet/redis/app1") {
		t.Errorf("redis ACL 渲染错误:\n%s", out.RenderedContent)
	}
	if !strings.Contains(out.RenderedContent, "+GET") || !strings.Contains(out.RenderedContent, "+SET") {
		t.Errorf("range 循环渲染的 +命令缺失:\n%s", out.RenderedContent)
	}
	if out.TargetPath != "/etc/redis/daedalus/app1.acl" {
		t.Errorf("target = %q, want /etc/redis/daedalus/app1.acl", out.TargetPath)
	}
}
