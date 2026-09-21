package main

// apply_tool_test.go —— blueprint_apply 的内存内 MCP 往返测试。
//
// 复用 list_tools_test.go 的 newTestApp/connectServer/callText 形态。
// apply 触发子进程(post_check / systemctl reload),故测试一律注入
// a.execCmd 假实现(after newTestApp 构造后覆写),并覆盖 a.outputDirs
// 为临时目录(render 的 /etc/... 目标路径不可写,测试手动塞 plan)。
//
// 覆盖:
//   - happy:render → apply 全链(token 校验 + 写文件 + post_check + reload);
//   - 5 失败:plan 不存在 / name 不匹配 / token 错配 / token 已消费(二次 apply)
//     / post_check 非零 rc;
//   - 2 回滚:post_check 失败 → 旧文件恢复;reload 失败 → 新文件删除。

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/blueprint"
)

// seedApplyPlan 手动构造一个已渲染的 plan 并放入 plan store,返回 plan_id。
// target 指向临时目录下的文件(测试不可写 /etc),token 由 GenerateConfirmToken
// 生成并同时存入 plan(与 render 行为一致)。
func seedApplyPlan(t *testing.T, a *app, name string) (planID, token string) {
	t.Helper()
	planID = newPlanID()
	tok := blueprint.GenerateConfirmToken(planID)
	tmp := t.TempDir()
	target := filepath.Join(tmp, "example.com.conf")
	a.outputDirs = []string{tmp}
	a.plans.put(planID, renderedPlan{
		Name:     name,
		Params:   map[string]any{"domain": "example.com"},
		Rendered: "server { server_name example.com; }",
		Target:   target,
		Token:    tok,
	})
	return planID, tok.Token
}

// TestApplyTool_Happy render→apply 全链成功:token 校验通过、文件写入、
// post_check 与 reload 均经假 execCmd 成功。
func TestApplyTool_Happy(t *testing.T) {
	a := newTestApp(t)
	a.execCmd = func(_ context.Context, name string, args ...string) ([]byte, error) {
		return nil, nil // 假子进程:总是成功
	}
	session, ctx := connectServer(t, a)
	planID, token := seedApplyPlan(t, a, "nginx-vhost")

	res, text := callText(t, session, ctx, "blueprint_apply", map[string]any{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": token,
	})
	if res.IsError {
		t.Fatalf("apply happy 失败: %s", text)
	}
	var out applyOut
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("结果非 applyOut(%v): %s", err, text)
	}
	if out.TxID != "(v1-direct)" || !out.PostCheckOK || !out.ReloadOK {
		t.Errorf("applyOut 字段异常: %+v", out)
	}
	if out.ConfigPath == "" || out.AppliedAt == "" {
		t.Errorf("config_path/applied_at 缺失: %+v", out)
	}
	// F2 R2:apply 必须把 remove 令牌回传客户端,且与 plan store 中的存档一致。
	if out.RemoveToken == "" {
		t.Errorf("remove_token 不应为空(否则 blueprint_remove 永不可达)")
	}
	if out.RemoveToken != a.plans.m[planID].RemoveToken.Token {
		t.Errorf("remove_token %q 与 plan store 中存档 %q 不一致", out.RemoveToken, a.plans.m[planID].RemoveToken.Token)
	}
	// 文件确实写入。
	data, err := os.ReadFile(out.ConfigPath)
	if err != nil || !strings.Contains(string(data), "server_name example.com") {
		t.Errorf("渲染内容未写入 %s(%v)", out.ConfigPath, err)
	}
	// plan 已从 store 取出后 token 已消费。
	if err := blueprint.VerifyConfirmToken(planID, blueprint.ConfirmToken{Token: token, PlanID: planID}); err == nil {
		t.Errorf("apply 后 token 应已消费")
	}
}

// TestApplyTool_PlanNotFound plan_id 不存在即拒。
func TestApplyTool_PlanNotFound(t *testing.T) {
	a := newTestApp(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	session, ctx := connectServer(t, a)

	res, text := callText(t, session, ctx, "blueprint_apply", map[string]any{
		"name": "nginx-vhost", "plan_id": "no-such-plan", "confirm_token": "x",
	})
	if !res.IsError || !strings.Contains(text, "no-such-plan") {
		t.Errorf("应报 plan 不存在, 得到: %s", text)
	}
}

// TestApplyTool_NameMismatch plan 的 Name 与入参不匹配即拒。
func TestApplyTool_NameMismatch(t *testing.T) {
	a := newTestApp(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	session, ctx := connectServer(t, a)
	planID, token := seedApplyPlan(t, a, "nginx-vhost")

	res, text := callText(t, session, ctx, "blueprint_apply", map[string]any{
		"name": "redis-acl", "plan_id": planID, "confirm_token": token,
	})
	if !res.IsError || !strings.Contains(text, "不匹配") {
		t.Errorf("应报 name 不匹配, 得到: %s", text)
	}
}

// TestApplyTool_TokenMismatch confirm_token 错配即拒。
func TestApplyTool_TokenMismatch(t *testing.T) {
	a := newTestApp(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	session, ctx := connectServer(t, a)
	planID, _ := seedApplyPlan(t, a, "nginx-vhost")

	res, text := callText(t, session, ctx, "blueprint_apply", map[string]any{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": "wrong-token",
	})
	if !res.IsError {
		t.Errorf("错配 token 应被拒, 得到: %s", text)
	}
}

// TestApplyTool_TokenConsumed 二次 apply(token 已消费)即拒。
func TestApplyTool_TokenConsumed(t *testing.T) {
	a := newTestApp(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	session, ctx := connectServer(t, a)
	planID, token := seedApplyPlan(t, a, "nginx-vhost")

	// 第一次 apply 成功(消费 token)。
	res1, text1 := callText(t, session, ctx, "blueprint_apply", map[string]any{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": token,
	})
	if res1.IsError {
		t.Fatalf("首次 apply 应成功: %s", text1)
	}
	// 第二次 apply 同 token → 已消费。
	res2, text2 := callText(t, session, ctx, "blueprint_apply", map[string]any{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": token,
	})
	if !res2.IsError {
		t.Errorf("二次 apply 应报 token 已消费, 得到: %s", text2)
	}
}

// TestApplyTool_PostCheckFails_RollbackOldFile post_check 非零 rc → 回滚恢复旧文件。
func TestApplyTool_PostCheckFails_RollbackOldFile(t *testing.T) {
	a := newTestApp(t)
	planID, token := seedApplyPlan(t, a, "nginx-vhost")
	// 预先写旧文件内容。
	old := "old config content"
	if err := os.WriteFile(a.plans.m[planID].Target, []byte(old), 0o644); err != nil {
		t.Fatalf("预写旧文件失败: %v", err)
	}
	// execCmd:nginx(第一条 post_check 命令)返回失败 → post_check 失败。
	a.execCmd = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "nginx" {
			return nil, errors.New("nginx -t 语法校验失败")
		}
		return nil, nil
	}
	session, ctx := connectServer(t, a)

	res, text := callText(t, session, ctx, "blueprint_apply", map[string]any{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": token,
	})
	if !res.IsError || !strings.Contains(text, "post_check") {
		t.Errorf("应报 post_check 失败, 得到: %s", text)
	}
	// 旧文件已恢复。
	data, err := os.ReadFile(a.plans.m[planID].Target)
	if err != nil || string(data) != old {
		t.Errorf("回滚后应恢复旧文件, 得到: %q (%v)", data, err)
	}
}

// TestApplyTool_ReloadFails_RollbackNewFile reload 失败 → 回滚删除新文件(无旧文件)。
func TestApplyTool_ReloadFails_RollbackNewFile(t *testing.T) {
	a := newTestApp(t)
	planID, token := seedApplyPlan(t, a, "nginx-vhost")
	// execCmd:post_check(nginx -t / systemctl is-active)成功,reload
	// (systemctl restart)失败 → reload 失败。按 args[0]=="restart" 区分。
	a.execCmd = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "restart" {
			return nil, errors.New("systemctl restart nginx 失败")
		}
		return nil, nil
	}
	session, ctx := connectServer(t, a)

	res, text := callText(t, session, ctx, "blueprint_apply", map[string]any{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": token,
	})
	if !res.IsError || !strings.Contains(text, "reload") {
		t.Errorf("应报 reload 失败, 得到: %s", text)
	}
	// 新文件已删除(无旧文件快照)。
	if _, err := os.Stat(a.plans.m[planID].Target); !os.IsNotExist(err) {
		t.Errorf("回滚后应删除新文件, stat err=%v", err)
	}
}
