package main

// ui_test.go —— `ui` 子命令(本地 Web UI)的 httptest 往返测试。
//
// 测试直连 uiServer.handler(),不监听真端口;每个请求模拟一次"本机浏览器
// 发起的同源请求"(RemoteAddr = 127.0.0.1、Host = 监听地址),四道防护各自
// 的负向用例只破坏其中一道,证明该道门独立生效。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// uiTestAddr 是测试用的监听地址;Host 白名单与端口都从它派生。
const uiTestAddr = "127.0.0.1:8787"

// newTestUIServer 构造可直连 handler 的 uiServer(不绑定真端口)。
func newTestUIServer(t *testing.T) (*uiServer, *app) {
	t.Helper()
	a := newTestApp(t)
	s, err := newUIServer(a, uiTestAddr)
	if err != nil {
		t.Fatalf("构造 uiServer 失败: %v", err)
	}
	return s, a
}

// uiRequest 构造一个"来自本机浏览器"的请求。httptest 默认 RemoteAddr 是
// 192.0.2.1:1234(非 loopback),不覆写就会被 RemoteAddr 门先拒。
func uiRequest(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.RemoteAddr = "127.0.0.1:54321"
	return r
}

// serve 把请求交给 handler 并返回响应记录器。
func serve(s *uiServer, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, r)
	return rec
}

// TestUIListRendersBlueprints 断言 GET / 返回 200 且列表页含全部蓝图 id 与
// "管理的资源"列(来自 blueprint_inspect 的 output_path_template / reload_service)。
func TestUIListRendersBlueprints(t *testing.T) {
	s, a := newTestUIServer(t)

	rec := serve(s, uiRequest("GET", "http://127.0.0.1:8787/", nil))
	if rec.Code != 200 {
		t.Fatalf("code=%d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, id := range a.reg.orderedIDs() {
		if !strings.Contains(body, id) {
			t.Errorf("列表页缺蓝图 id %q", id)
		}
	}
	// "管理的资源"列:路径模板 + reload 服务名。
	if !strings.Contains(body, "/etc/nginx/conf.d/{domain}.conf") {
		t.Errorf("列表页缺 output_path_template")
	}
	if !strings.Contains(body, "reload · nginx") {
		t.Errorf("列表页缺 reload_service 列")
	}
	// 设计稿的假数据标记与骨架页脚必须已删除。
	if strings.Contains(body, "假数据") {
		t.Errorf("正式页面不应残留 假数据 标记")
	}
}

// TestUIListResourceColumnDegrades 单条 inspect 失败只让该行的资源列显示 "—",
// 不许整页 500。
func TestUIListResourceColumnDegrades(t *testing.T) {
	s, _ := newTestUIServer(t)
	// 模拟"逐条 inspect 失败":只让 nginx-vhost 这条取不到详情。
	orig := s.detailOf
	s.detailOf = func(a *app, id string) (blueprintDetail, bool) {
		if id == "nginx-vhost" {
			return blueprintDetail{}, false
		}
		return orig(a, id)
	}

	rec := serve(s, uiRequest("GET", "http://127.0.0.1:8787/", nil))
	if rec.Code != 200 {
		t.Fatalf("单条 inspect 失败不应让整页失败: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "—") {
		t.Errorf("资源列缺失时该显示 —")
	}
	// 其余行不受影响(整页没有因为一条失败而瘫痪)。
	if !strings.Contains(rec.Body.String(), "/etc/redis/daedalus/{user}.acl") {
		t.Errorf("其它蓝图的资源列不应受单条失败影响")
	}
}

// TestUIGuard_RejectsForeignHost 防护 1:Host 不在白名单(防 DNS rebinding)→ 403。
func TestUIGuard_RejectsForeignHost(t *testing.T) {
	s, _ := newTestUIServer(t)
	rec := serve(s, uiRequest("GET", "http://evil.example.com/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Host=evil.example.com 应 403, 得到 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Host") {
		t.Errorf("403 应说明被拒原因(Host), 得到: %s", rec.Body.String())
	}
}

// TestUIGuard_RejectsNonLoopbackRemoteAddr 防护 4:RemoteAddr 非 loopback → 403。
func TestUIGuard_RejectsNonLoopbackRemoteAddr(t *testing.T) {
	s, _ := newTestUIServer(t)
	r := uiRequest("GET", "http://127.0.0.1:8787/", nil)
	r.RemoteAddr = "10.1.2.3:4444"
	rec := serve(s, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("非 loopback RemoteAddr 应 403, 得到 %d", rec.Code)
	}
}

// TestUIGuard_PostRequiresCustomHeader 防护 2:POST /api/* 缺 X-Daedalus-Ui → 403;
// 带上该头才放行(跨站表单无法设置自定义头)。
func TestUIGuard_PostRequiresCustomHeader(t *testing.T) {
	s, a := newTestUIServer(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	payload := `{"name":"nginx-vhost","params":{"domain":"example.com"}}`

	rec := serve(s, uiRequest("POST", "http://127.0.0.1:8787/api/render", strings.NewReader(payload)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("缺少 X-Daedalus-Ui 头应 403, 得到 %d body=%s", rec.Code, rec.Body.String())
	}

	ok := uiRequest("POST", "http://127.0.0.1:8787/api/render", strings.NewReader(payload))
	ok.Header.Set("X-Daedalus-Ui", "1")
	if rec := serve(s, ok); rec.Code == http.StatusForbidden {
		t.Fatalf("带自定义头的同源 POST 不应 403: %s", rec.Body.String())
	}
}

// TestUIGuard_RejectsCrossSiteOrigin 防护 3:POST 带跨站 Origin → 403。
func TestUIGuard_RejectsCrossSiteOrigin(t *testing.T) {
	s, _ := newTestUIServer(t)
	payload := `{"name":"nginx-vhost","params":{"domain":"example.com"}}`

	r := uiRequest("POST", "http://127.0.0.1:8787/api/render", strings.NewReader(payload))
	r.Header.Set("X-Daedalus-Ui", "1")
	r.Header.Set("Origin", "http://evil.example.com")
	if rec := serve(s, r); rec.Code != http.StatusForbidden {
		t.Fatalf("跨站 Origin 应 403, 得到 %d", rec.Code)
	}

	// 同源 Origin 放行。
	r2 := uiRequest("POST", "http://127.0.0.1:8787/api/render", strings.NewReader(payload))
	r2.Header.Set("X-Daedalus-Ui", "1")
	r2.Header.Set("Origin", "http://127.0.0.1:8787")
	if rec := serve(s, r2); rec.Code == http.StatusForbidden {
		t.Fatalf("同源 Origin 不应 403: %s", rec.Body.String())
	}
}

// TestParseListenListenAddr 钉 --listen 的口径:默认 127.0.0.1:8787、off 关闭、
// 非 loopback 拒绝启动。
func TestParseListenListenAddr(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantOff bool
		wantErr bool
	}{
		{"", uiDefaultListen, false, false},
		{"off", "", true, false},
		{"127.0.0.1:9000", "127.0.0.1:9000", false, false},
		{"localhost:8787", "localhost:8787", false, false},
		{"0.0.0.0:8787", "", false, true},
		{"192.168.1.5:8787", "", false, true},
		{"[::]:8787", "", false, true},
		{"127.0.0.1", "", false, true},
	}
	for _, c := range cases {
		got, off, err := parseListen(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseListen(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if off != c.wantOff || got != c.want {
			t.Errorf("parseListen(%q) = (%q,%v), want (%q,%v)", c.in, got, off, c.want, c.wantOff)
		}
	}
}

// TestUIRenderFragment 断言 POST /api/render 返回的片段含 plan_id、目标路径、
// 至少一条 + 与一条 - 的 diff 行。
func TestUIRenderFragment(t *testing.T) {
	s, a := newTestUIServer(t)
	// 预置一个旧目标文件,让 diff 同时出现 + 与 -;输出目录改到临时目录,
	// 避免真的往 /etc/nginx 里安装配置(registry 是每个测试独立构造的)。
	dir := t.TempDir()
	target := dir + "/example.com.conf"
	if err := os.WriteFile(target, []byte("placeholder {\n    listen 8080;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a.outputDirs = []string{dir}
	cb, _ := a.reg.get("nginx-vhost")
	cb.Blueprint.OutputPathTmpl = dir + "/{domain}.conf"

	body := postJSON(t, s, "/api/render", map[string]any{
		"name": "nginx-vhost",
		// 表单提交的是字符串原值,类型由服务端按 schema 归一化。
		"params": map[string]string{"domain": "example.com", "ssl": "on", "listen_ports": "80, 443"},
	})
	if !strings.Contains(body, "plan_id") {
		t.Errorf("片段缺 plan_id")
	}
	if !strings.Contains(body, target) {
		t.Errorf("片段缺 target_path %q", target)
	}
	if !strings.Contains(body, `class="ln add"`) {
		t.Errorf("片段缺新增行 (+): %s", body)
	}
	if !strings.Contains(body, `class="ln del"`) {
		t.Errorf("片段缺删除行 (-): %s", body)
	}
	// confirm_token 只允许出现在 <form> 的 hidden 字段里。
	assertTokenOnlyInHidden(t, body)
}

// TestUIRenderFragmentNewFile 目标文件尚不存在时,blueprint_render 返回空 diff;
// UI 必须按"新建文件"展示为全部新增行(设计稿的新建文件视图),而不是空白差异。
func TestUIRenderFragmentNewFile(t *testing.T) {
	s, a := newTestUIServer(t)
	dir := t.TempDir() // 空目录:目标文件不存在
	a.outputDirs = []string{dir}
	cb, _ := a.reg.get("nginx-vhost")
	cb.Blueprint.OutputPathTmpl = dir + "/{domain}.conf"

	body := postJSON(t, s, "/api/render", map[string]any{
		"name":   "nginx-vhost",
		"params": map[string]string{"domain": "example.com"},
	})
	if !strings.Contains(body, `class="ln add"`) {
		t.Errorf("新建文件应展示新增行: %s", body)
	}
	if strings.Contains(body, `class="ln del"`) {
		t.Errorf("新建文件不应有删除行: %s", body)
	}
	if !strings.Contains(body, "新建文件") {
		t.Errorf("差异统计应标注新建文件")
	}
	if !strings.Contains(body, "server_name example.com;") {
		t.Errorf("差异行应含渲染内容: %s", body)
	}
}

// TestUIRenderErrorKeepsValues 渲染失败:HTTP 200 + 片段含 role="alert",
// 且用户已填的值被保留(不清空表单)。
func TestUIRenderErrorKeepsValues(t *testing.T) {
	s, _ := newTestUIServer(t)
	body := postJSONStatus(t, s, "/api/render", map[string]any{
		"name":   "nginx-vhost",
		"params": map[string]string{"domain": "NOT A DOMAIN"},
	}, http.StatusOK)
	if !strings.Contains(body, `role="alert"`) {
		t.Errorf("失败片段缺 role=alert: %s", body)
	}
	if !strings.Contains(body, `value="NOT A DOMAIN"`) {
		t.Errorf("失败后应保留用户填写的值: %s", body)
	}
}

// postJSON 以同源 POST 提交 JSON,断言 200 并返回响应体。
func postJSON(t *testing.T, s *uiServer, path string, payload any) string {
	t.Helper()
	return postJSONStatus(t, s, path, payload, http.StatusOK)
}

// postJSONStatus 以同源 POST 提交 JSON,断言状态码并返回响应体。
func postJSONStatus(t *testing.T, s *uiServer, path string, payload any, wantStatus int) string {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("序列化请求失败: %v", err)
	}
	r := uiRequest("POST", "http://127.0.0.1:8787"+path, strings.NewReader(string(data)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Daedalus-Ui", "1")
	rec := serve(s, r)
	if rec.Code != wantStatus {
		t.Fatalf("%s code=%d, want %d; body=%s", path, rec.Code, wantStatus, rec.Body.String())
	}
	return rec.Body.String()
}

// assertTokenOnlyInHidden 断言响应体里任何 confirm_token 值都只出现在
// <input type="hidden"> 的 value 属性里:不在 data-* 属性、不在内联 <script>、
// 不在 localStorage 相关文本中。
func assertTokenOnlyInHidden(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, "data-confirm") {
		t.Errorf("confirm_token 不得进入 data-* 属性")
	}
	tokens := hiddenTokenValues(body)
	if len(tokens) == 0 {
		t.Fatalf("片段里没有 hidden confirm_token 字段: %s", body)
	}
	for _, tok := range tokens {
		if tok == "" {
			t.Errorf("hidden confirm_token 为空")
			continue
		}
		n := strings.Count(body, tok)
		if n != 1 {
			t.Errorf("confirm_token 出现 %d 次(应仅在 hidden value 里一次)", n)
		}
		t.Logf("confirm_token 出现 %d 次,且不在 data-* 属性、不在内联 JS、不在 localStorage", n)
		if strings.Contains(body, "localStorage") && strings.Contains(body[strings.Index(body, "localStorage"):], tok) {
			t.Errorf("confirm_token 不得进 localStorage")
		}
		if script := inlineScripts(body); strings.Contains(script, tok) {
			t.Errorf("confirm_token 不得出现在内联 JS 里")
		}
	}
}

// hiddenTokenValues 抽取所有 name="confirm_token" 的 hidden input 的 value。
func hiddenTokenValues(body string) []string {
	return hiddenInputValues(body, "confirm_token")
}

// hiddenInputValues 抽取所有指定名字的 <input type="hidden"> 的 value。
func hiddenInputValues(body, name string) []string {
	var out []string
	for _, seg := range strings.Split(body, "<input")[1:] {
		tag := seg
		if i := strings.IndexByte(tag, '>'); i >= 0 {
			tag = tag[:i]
		}
		if !strings.Contains(tag, `name="`+name+`"`) || !strings.Contains(tag, `type="hidden"`) {
			continue
		}
		out = append(out, attrValue(tag, "value"))
	}
	return out
}

// hiddenInputValue 取第一个指定名字的 hidden input 的 value。
func hiddenInputValue(body, name string) string {
	if v := hiddenInputValues(body, name); len(v) > 0 {
		return v[0]
	}
	return ""
}

// inlineScripts 把所有 <script>…</script> 的内容拼起来。
func inlineScripts(body string) string {
	var b strings.Builder
	for i := 0; ; {
		start := strings.Index(body[i:], "<script")
		if start < 0 {
			return b.String()
		}
		start += i
		start = strings.Index(body[start:], ">")
		if start < 0 {
			return b.String()
		}
		start += i + 1
		end := strings.Index(body[start:], "</script>")
		if end < 0 {
			return b.String()
		}
		b.WriteString(body[start : start+end])
		i = start + end
	}
}

// attrValue 从标签文本里取 attr="…" 的值(测试专用,足够覆盖 html/template
// 的转义输出)。
func attrValue(tag, attr string) string {
	key := attr + `="`
	i := strings.Index(tag, key)
	if i < 0 {
		return ""
	}
	rest := tag[i+len(key):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}
