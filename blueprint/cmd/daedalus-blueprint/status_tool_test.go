package main

// status_tool_test.go —— blueprint_status / blueprint_remove 的内存内 MCP 测试。
//
// 复用 list_tools_test.go 的 newTestApp/connectServer/callText 形态。
// status 只读(无 execCmd 依赖);remove 走 VerifyConfirmToken + 删文件 +
// reload(a.execCmd 注入缝)。
//
// 覆盖:
//   - status:happy(未知 name 报错 / 有文件 installed=true);
//   - remove:happy(先 seed + 删文件 + reload)/
//     token 校验失败 / 目标文件不存在。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/blueprint"
)

// TestStatusTool_UnknownName 未知蓝图报错。
func TestStatusTool_UnknownName(t *testing.T) {
	a := newTestApp(t)
	session, ctx := connectServer(t, a)

	res, text := callText(t, session, ctx, "blueprint_status", map[string]any{"name": "no-such"})
	if !res.IsError || !strings.Contains(text, "no-such") {
		t.Errorf("未知蓝图应报错, 得到: %s", text)
	}
}

// TestStatusTool_Happy 已知蓝图返回状态结构(未安装场景)。
func TestStatusTool_Happy(t *testing.T) {
	a := newTestApp(t)
	session, ctx := connectServer(t, a)

	res, text := callText(t, session, ctx, "blueprint_status", map[string]any{"name": "nginx-vhost"})
	if res.IsError {
		t.Fatalf("status happy 失败: %s", text)
	}
	var out statusOut
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("结果非 statusOut(%v): %s", err, text)
	}
	if out.Name != "nginx-vhost" {
		t.Errorf("name = %q, want nginx-vhost", out.Name)
	}
	if out.TargetPath == "" {
		t.Errorf("target_path 不应为空")
	}
}

// TestStatusTool_Installed 目标目录存在文件时 installed=true 且 content_hash 非空。
func TestStatusTool_Installed(t *testing.T) {
	a := newTestApp(t)
	// 在 outputDirs 第一个目录放一个文件,模拟已安装。
	dir := a.outputDirs[0]
	if dir == "" {
		t.Skip("outputDirs 为空")
	}
	_ = os.MkdirAll(dir, 0o755)
	cfg := filepath.Join(dir, "test-vhost.conf")
	if err := os.WriteFile(cfg, []byte("server { server_name test; }"), 0o644); err != nil {
		t.Skipf("无法写测试目录(%v), 跳过", err)
	}
	session, ctx := connectServer(t, a)

	res, text := callText(t, session, ctx, "blueprint_status", map[string]any{"name": "nginx-vhost"})
	if res.IsError {
		t.Fatalf("status 失败: %s", text)
	}
	var out statusOut
	_ = json.Unmarshal([]byte(text), &out)
	if !out.Installed {
		t.Errorf("目标目录有文件但 installed=false")
	}
	if len(out.ContentHash) != 12 {
		t.Errorf("content_hash 应为 12 位 sha256 前缀, 得到 %q", out.ContentHash)
	}
}

// seedAppliedPlan 构造一个"已 apply"的 plan:seed 进 store + 消费其 token
// (模拟 blueprint_apply 成功后 token 已消费)+ 置位 Applied(F2 R1 修复后
// remove 以 Applied 标志判断"已应用")+ 写目标文件到临时目录。
// 返回 plan_id 与 remove 命名空间的 token。
func seedAppliedPlan(t *testing.T, a *app, name string) (planID, removeToken string) {
	t.Helper()
	planID = newPlanID()
	tok := blueprint.GenerateConfirmToken(planID)
	// 消费 plan token(模拟 apply 成功)。
	if err := blueprint.VerifyConfirmToken(planID, tok); err != nil {
		t.Fatalf("预消费 plan token 失败: %v", err)
	}
	tmp := t.TempDir()
	target := filepath.Join(tmp, "example.com.conf")
	if err := os.WriteFile(target, []byte("server {}"), 0o644); err != nil {
		t.Fatalf("写目标文件失败: %v", err)
	}
	a.outputDirs = []string{tmp}
	ref := "remove:" + name
	removeTok := blueprint.GenerateConfirmToken(ref)
	a.plans.put(planID, renderedPlan{
		Name:        name,
		Params:      map[string]any{"domain": "example.com"},
		Rendered:    "server {}",
		Target:      target,
		Token:       tok,
		RemoveToken: removeTok,
		Applied:     true,
	})
	return planID, removeTok.Token
}

// TestRemoveTool_Happy 已 apply 的 plan → remove:删文件 + reload(假 execCmd 成功)。
func TestRemoveTool_Happy(t *testing.T) {
	a := newTestApp(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	session, ctx := connectServer(t, a)
	planID, removeTok := seedAppliedPlan(t, a, "nginx-vhost")

	res, text := callText(t, session, ctx, "blueprint_remove", map[string]any{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": removeTok,
	})
	if res.IsError {
		t.Fatalf("remove happy 失败: %s", text)
	}
	var out removeOut
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("结果非 removeOut(%v): %s", err, text)
	}
	if !out.Removed || out.ConfigPath == "" {
		t.Errorf("removeOut 异常: %+v", out)
	}
	if _, err := os.Stat(out.ConfigPath); !os.IsNotExist(err) {
		t.Errorf("文件应已删除, stat err=%v", err)
	}
}

// TestRemoveTool_EmptyToken remove 的 confirm_token 为空 → 被拒。
func TestRemoveTool_EmptyToken(t *testing.T) {
	a := newTestApp(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	session, ctx := connectServer(t, a)
	planID, _ := seedAppliedPlan(t, a, "nginx-vhost")

	res, text := callText(t, session, ctx, "blueprint_remove", map[string]any{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": "",
	})
	if !res.IsError {
		t.Errorf("空 token 应被拒, 得到: %s", text)
	}
}

// TestRemoveTool_PlanNotApplied plan 未 apply(Applied=false)→ 被拒。
// F2 R1 回归证明:被拒的 remove 不得消费 apply 令牌——remove 被拒后,
// 用原始 confirm_token 走 blueprint_apply 仍必须成功(令牌未被误消费)。
func TestRemoveTool_PlanNotApplied(t *testing.T) {
	a := newTestApp(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	session, ctx := connectServer(t, a)

	// seed 一个 plan 但不 apply(Applied 保持零值 false,模拟 render 后未 apply)。
	planID := newPlanID()
	tok := blueprint.GenerateConfirmToken(planID)
	tmp := t.TempDir()
	target := filepath.Join(tmp, "example.com.conf")
	_ = os.WriteFile(target, []byte("server {}"), 0o644)
	a.outputDirs = []string{tmp}
	a.plans.put(planID, renderedPlan{
		Name: "nginx-vhost", Params: nil, Rendered: "server {}", Target: target, Token: tok,
	})
	ref := "remove:nginx-vhost"
	removeTok := blueprint.GenerateConfirmToken(ref)

	res, text := callText(t, session, ctx, "blueprint_remove", map[string]any{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": removeTok.Token,
	})
	if !res.IsError {
		t.Errorf("未 apply 的 plan 应被拒, 得到: %s", text)
	}

	// F2 R1 回归:被拒的 remove 未消费 apply 令牌 → 原始 confirm_token 仍可成功 apply。
	res2, text2 := callText(t, session, ctx, "blueprint_apply", map[string]any{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": tok.Token,
	})
	if res2.IsError {
		t.Errorf("remove 被拒后 apply 应仍成功(令牌未被误消费), 得到: %s", text2)
	}
}

// TestRemoveTool_NoFile plan 已 apply 但目标文件不存在 → 被拒。
func TestRemoveTool_NoFile(t *testing.T) {
	a := newTestApp(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	session, ctx := connectServer(t, a)

	// seed 已 apply 的 plan 但不写文件。
	planID := newPlanID()
	tok := blueprint.GenerateConfirmToken(planID)
	_ = blueprint.VerifyConfirmToken(planID, tok)
	tmp := t.TempDir()
	target := filepath.Join(tmp, "nonexistent.conf")
	a.outputDirs = []string{tmp}
	a.plans.put(planID, renderedPlan{
		Name: "nginx-vhost", Params: nil, Rendered: "server {}", Target: target, Token: tok, Applied: true,
	})
	ref := "remove:nginx-vhost"
	removeTok := blueprint.GenerateConfirmToken(ref)

	res, text := callText(t, session, ctx, "blueprint_remove", map[string]any{
		"name": "nginx-vhost", "plan_id": planID, "confirm_token": removeTok.Token,
	})
	if !res.IsError {
		t.Errorf("目标文件不存在应被拒, 得到: %s", text)
	}
}
