package main

// ui_apply_test.go —— 应用页(POST /api/apply)与 diff 解析的测试。
//
// 应用是危险动作:服务端只认 confirm_token(前端"我理解"勾选纯属 UX),
// 过期由服务端按 plan store 里的 Token.Expires 判,令牌单次有效且响应不回声
// 令牌值。

import (
	"context"
	"strings"
	"testing"
	"time"
)

// renderViaUI 走一次真实 POST /api/render,返回 render 片段、plan_id 与令牌。
// 输出目录与路径模板改到临时目录,避免真的往 /etc/nginx 安装配置。
func renderViaUI(t *testing.T, s *uiServer, a *app) (body, planID, token string) {
	t.Helper()
	dir := t.TempDir()
	cb, ok := a.reg.get("nginx-vhost")
	if !ok {
		t.Fatal("registry 缺 nginx-vhost")
	}
	cb.Blueprint.OutputPathTmpl = dir + "/{domain}.conf"
	a.outputDirs = []string{dir}

	body = postJSON(t, s, "/api/render", map[string]any{
		"name":   "nginx-vhost",
		"params": map[string]string{"domain": "example.com"},
	})
	planID = hiddenInputValue(body, "plan_id")
	token = hiddenInputValue(body, "confirm_token")
	if planID == "" || token == "" {
		t.Fatalf("render 片段缺 plan_id/confirm_token: %s", body)
	}
	return body, planID, token
}

// TestUIApply_ServerOnlyTrustsToken 未勾选前端确认框不影响服务端:服务端只认
// confirm_token(勾选是 UX,不是授权)。
func TestUIApply_ServerOnlyTrustsToken(t *testing.T) {
	s, a := newTestUIServer(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	_, planID, token := renderViaUI(t, s, a)

	// 请求体里没有任何"我已确认"字段。
	body := postJSON(t, s, "/api/apply", map[string]string{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": token,
	})
	if !strings.Contains(body, "已应用") {
		t.Fatalf("带正确令牌的 apply 应成功, 得到: %s", body)
	}
}

// TestUIApply_ExpiredTokenRejected 过期 plan(token 的 Expires 调到过去)→
// 403 且文案要求"回到预览重新渲染"。
func TestUIApply_ExpiredTokenRejected(t *testing.T) {
	s, a := newTestUIServer(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	_, planID, token := renderViaUI(t, s, a)

	plan, ok := a.plans.get(planID)
	if !ok {
		t.Fatalf("plan %q 未落入 plan store", planID)
	}
	plan.Token.Expires = time.Now().Add(-time.Minute).UnixMilli()
	a.plans.put(planID, plan)

	body := postJSONStatus(t, s, "/api/apply", map[string]string{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": token,
	}, 403)
	if !strings.Contains(body, "过期") {
		t.Errorf("403 片段应说明令牌已过期: %s", body)
	}
	if !strings.Contains(body, "请回到预览重新渲染") {
		t.Errorf("403 片段应指回预览页重新渲染: %s", body)
	}
	// 过期时不得再渲染可提交的应用表单。
	if strings.Contains(body, `id="apply-form"`) {
		t.Errorf("过期后不应再渲染应用表单")
	}
}

// TestUIApply_Success 正确令牌 → 返回片段含 tx_id / post_check_ok / reload_ok。
func TestUIApply_Success(t *testing.T) {
	s, a := newTestUIServer(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	_, planID, token := renderViaUI(t, s, a)

	body := postJSON(t, s, "/api/apply", map[string]string{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": token,
	})
	for _, want := range []string{"tx_id", "post_check_ok", "reload_ok", "config_path"} {
		if !strings.Contains(body, want) {
			t.Errorf("成功片段缺 %q: %s", want, body)
		}
	}
	if !strings.Contains(body, `<span class="yes">true</span>`) {
		t.Errorf("post_check_ok/reload_ok 应显示 true")
	}
	// 令牌已消费:成功后片段里不再保留 hidden 令牌。
	if strings.Contains(body, `name="confirm_token"`) {
		t.Errorf("apply 成功后不应再下发 confirm_token")
	}
}

// TestUIApply_TokenSingleUse 同一 token 第二次 → 失败,且响应不回声令牌值。
func TestUIApply_TokenSingleUse(t *testing.T) {
	s, a := newTestUIServer(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	_, planID, token := renderViaUI(t, s, a)

	postJSON(t, s, "/api/apply", map[string]string{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": token,
	})
	body := postJSONStatus(t, s, "/api/apply", map[string]string{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": token,
	}, 403)
	if !strings.Contains(body, "失败") {
		t.Errorf("二次 apply 应显示失败: %s", body)
	}
	if strings.Contains(body, token) {
		t.Errorf("失败片段不得回声 confirm_token")
	}
}

// TestUIApply_UnknownPlan plan store 里没有(进程重启)→ 403 且提示重新渲染。
func TestUIApply_UnknownPlan(t *testing.T) {
	s, a := newTestUIServer(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	body := postJSONStatus(t, s, "/api/apply", map[string]string{
		"name": "nginx-vhost", "plan_id": "no-such-plan", "confirm_token": "x",
	}, 403)
	if !strings.Contains(body, "重新渲染") {
		t.Errorf("plan 不存在应提示重新渲染: %s", body)
	}
}

// TestParseUnifiedDiff 钉 diff 解析:紧凑形态填行号、+ 行无旧行号、
// `\ No newline at end of file` 保留可读、空 diff 视为新文件全为新增。
func TestParseUnifiedDiff(t *testing.T) {
	lines := parseUnifiedDiff("  keep\n- old\n+ new\n\\ No newline at end of file")
	if len(lines) != 4 {
		t.Fatalf("行数 = %d, want 4(不得吞行): %+v", len(lines), lines)
	}
	if lines[0].Class != "ctx" || lines[0].OldNo != "1" || lines[0].NewNo != "1" || lines[0].Text != "keep" {
		t.Errorf("上下文行解析错: %+v", lines[0])
	}
	if lines[1].Class != "del" || lines[1].OldNo != "2" || lines[1].NewNo != "" || lines[1].Text != "old" {
		t.Errorf("删除行解析错: %+v", lines[1])
	}
	if lines[2].Class != "add" || lines[2].NewNo != "2" || lines[2].OldNo != "" || lines[2].Text != "new" {
		t.Errorf("新增行解析错: %+v", lines[2])
	}
	if !strings.Contains(lines[3].Text, "No newline at end of file") {
		t.Errorf(`"\ No newline" 标记行必须保留可读: %+v`, lines[3])
	}

	// 标准 unified diff(hunk 头)也支持:行号按 hunk 头重置。
	std := parseUnifiedDiff("@@ -10,2 +10,3 @@\n ctx\n-old\n+new")
	if len(std) != 4 || std[0].Class != "hunk" {
		t.Fatalf("hunk 头解析错: %+v", std)
	}
	if std[1].OldNo != "10" || std[2].OldNo != "11" || std[3].NewNo != "11" {
		t.Errorf("hunk 后行号未按头重置: %+v", std)
	}

	if got := parseUnifiedDiff(""); got != nil {
		t.Errorf("空 diff 应返回 nil, 得到 %+v", got)
	}
}
