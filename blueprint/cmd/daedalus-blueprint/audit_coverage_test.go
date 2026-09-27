package main

// audit_coverage_test.go —— blueprint 六工具的审计覆盖守门。
//
// 两条不变式:
//  1. 每次工具调用恰落一条哈希链条目(拒绝路径也不例外)——漏记拒绝即给
//     agent 留下一条"试探白名单/令牌而无痕"的通道;
//  2. 结局 token 只用全仓词表 success / denied / error(apply/remove 曾用
//     legacy "ok",消费方 copilot 的 AuditOutcome 联合类型里根本没有它)。
//
// 守门测试还拿 tools/list 的实际注册表比对覆盖表:新增工具却忘了在
// choke point 落审计,这里直接红。

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/audit"
	"github.com/Daedalusys/daedalus-sdk/blueprint"
)

type auditEntry struct {
	Identity string         `json:"identity"`
	Tool     string         `json:"tool"`
	Args     map[string]any `json:"args"`
	Outcome  string         `json:"outcome"`
}

// mustSingleEntry 断言 logPath 里恰有一条属于 wantTool/wantOutcome 的条目,
// 并以 audit.Verify 证链完好;返回该条目的 args 供调用方再查内容。
func mustSingleEntry(t *testing.T, logPath, wantTool, wantOutcome string) auditEntry {
	t.Helper()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("读取审计日志失败: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("审计条数 = %d, want 1(单次调用恰一条):\n%s", len(lines), raw)
	}
	var e auditEntry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("审计条目解析失败: %v\n%s", err, lines[0])
	}
	if e.Identity != blueprintIdentity || e.Tool != wantTool || e.Outcome != wantOutcome {
		t.Fatalf("条目字段漂移: %+v(want %s/%s)", e, wantTool, wantOutcome)
	}
	if n, err := audit.Verify(logPath); err != nil || n != 1 {
		t.Fatalf("audit.Verify = (%d, %v), want (1, nil)", n, err)
	}
	return e
}

// newAuditLog 把本轮审计链指向测试独占文件(t.Setenv 退出即复原,精确计数不受污染)。
func newAuditLog(t *testing.T) string {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv(audit.EnvLogPath, logPath)
	return logPath
}

// applyAuditCase 走一次 blueprint_apply 并断言审计结局;prep 负责播种 plan 与
// 入参(默认给一份可成功的),execFail 用于让 post_check / reload 假失败。
func applyAuditCase(t *testing.T, wantOutcome string, prep func(t *testing.T, a *app) map[string]any,
	execFail func(name string, args []string) error) auditEntry {
	t.Helper()
	logPath := newAuditLog(t)
	a := newTestApp(t)
	a.execCmd = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if execFail != nil {
			if err := execFail(name, args); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	session, ctx := connectServer(t, a)
	if prep == nil {
		prep = func(t *testing.T, a *app) map[string]any {
			planID, token := seedApplyPlan(t, a, "nginx-vhost")
			return map[string]any{"name": "nginx-vhost", "plan_id": planID, "confirm_token": token}
		}
	}
	in := prep(t, a)

	res, text := callText(t, session, ctx, "blueprint_apply", in)
	if wantErr := wantOutcome != "success"; res.IsError != wantErr {
		t.Fatalf("outcome=%s 与工具结果不符(isError=%v): %s", wantOutcome, res.IsError, text)
	}
	return mustSingleEntry(t, logPath, "blueprint_apply", wantOutcome)
}

// reseedPlan 取回已播种 plan 的当前存档(测试改写 Target/Token 后再 put 回)。
func reseedPlan(t *testing.T, a *app, planID string) renderedPlan {
	t.Helper()
	p, ok := a.plans.get(planID)
	if !ok {
		t.Fatalf("plan %s 不存在", planID)
	}
	return p
}

// TestAudit_ApplyEveryGateAppendsOneEntry 钉 blueprint_apply 的全部分支门:
// 各拒绝门记 denied、写盘/post_check/reload 故障记 error、完成记 success,
// 每条路径恰落一个结局条目(此前拒绝门一条都不写)。
func TestAudit_ApplyEveryGateAppendsOneEntry(t *testing.T) {
	t.Run("success 带 target", func(t *testing.T) {
		e := applyAuditCase(t, "success", nil, nil)
		if e.Args["name"] != "nginx-vhost" || e.Args["target"] == nil || e.Args["target"] == "" {
			t.Errorf("成功条目应含 name/target: %v", e.Args)
		}
		if _, ok := e.Args["confirm_token"]; ok {
			t.Errorf("confirm_token 严禁进链: %v", e.Args)
		}
		if _, ok := e.Args["rendered"]; ok {
			t.Errorf("渲染内容严禁进链: %v", e.Args)
		}
	})

	t.Run("plan 不存在", func(t *testing.T) {
		applyAuditCase(t, "denied", func(_ *testing.T, _ *app) map[string]any {
			return map[string]any{"name": "nginx-vhost", "plan_id": "no-such-plan", "confirm_token": "x"}
		}, nil)
	})

	t.Run("name 串用", func(t *testing.T) {
		applyAuditCase(t, "denied", func(t *testing.T, a *app) map[string]any {
			planID, token := seedApplyPlan(t, a, "nginx-vhost")
			return map[string]any{"name": "redis-acl", "plan_id": planID, "confirm_token": token}
		}, nil)
	})

	t.Run("plan 无确认令牌", func(t *testing.T) {
		applyAuditCase(t, "denied", func(t *testing.T, a *app) map[string]any {
			planID, token := seedApplyPlan(t, a, "nginx-vhost")
			p := reseedPlan(t, a, planID)
			p.Token = blueprint.ConfirmToken{}
			a.plans.put(planID, p)
			return map[string]any{"name": "nginx-vhost", "plan_id": planID, "confirm_token": token}
		}, nil)
	})

	t.Run("令牌错配", func(t *testing.T) {
		applyAuditCase(t, "denied", func(t *testing.T, a *app) map[string]any {
			planID, _ := seedApplyPlan(t, a, "nginx-vhost")
			return map[string]any{"name": "nginx-vhost", "plan_id": planID, "confirm_token": "wrong-token"}
		}, nil)
	})

	t.Run("令牌已消费", func(t *testing.T) {
		logPath := newAuditLog(t)
		a := newTestApp(t)
		a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
		session, ctx := connectServer(t, a)
		planID, token := seedApplyPlan(t, a, "nginx-vhost")
		in := map[string]any{"name": "nginx-vhost", "plan_id": planID, "confirm_token": token}
		callText(t, session, ctx, "blueprint_apply", in)
		if e := mustSingleEntry(t, logPath, "blueprint_apply", "success"); e.Tool == "" {
			t.Fatal("unreachable")
		}
		// 第二次调用:令牌已被首次消费 → denied,且**再次**落一条(两次调用两条)。
		res, _ := callText(t, session, ctx, "blueprint_apply", in)
		if !res.IsError {
			t.Fatal("二次 apply 应被拒")
		}
		raw, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(strings.Split(strings.TrimRight(string(raw), "\n"), "\n")); n != 2 {
			t.Fatalf("两次调用应恰两条条目, 实得 %d:\n%s", n, raw)
		}
		var second auditEntry
		if err := json.Unmarshal([]byte(strings.Split(strings.TrimRight(string(raw), "\n"), "\n")[1]), &second); err != nil {
			t.Fatal(err)
		}
		if second.Outcome != "denied" {
			t.Errorf("二次 apply 条目结局 = %s, want denied", second.Outcome)
		}
	})

	t.Run("目标越出白名单", func(t *testing.T) {
		applyAuditCase(t, "denied", func(t *testing.T, a *app) map[string]any {
			planID, token := seedApplyPlan(t, a, "nginx-vhost")
			p := reseedPlan(t, a, planID)
			p.Target = filepath.Join(t.TempDir(), "outside-dir", "x.conf")
			a.plans.put(planID, p)
			return map[string]any{"name": "nginx-vhost", "plan_id": planID, "confirm_token": token}
		}, nil)
	})

	t.Run("目标为符号链接", func(t *testing.T) {
		applyAuditCase(t, "denied", func(t *testing.T, a *app) map[string]any {
			planID, token := seedApplyPlan(t, a, "nginx-vhost")
			p := reseedPlan(t, a, planID)
			link := p.Target
			p.Target = filepath.Join(filepath.Dir(link), "via-symlink.conf")
			a.plans.put(planID, p)
			if err := os.Symlink(filepath.Join(t.TempDir(), "escape.conf"), p.Target); err != nil {
				t.Skipf("符号链接不可用: %v", err)
			}
			return map[string]any{"name": "nginx-vhost", "plan_id": planID, "confirm_token": token}
		}, nil)
	})

	t.Run("蓝图未注册", func(t *testing.T) {
		applyAuditCase(t, "denied", func(t *testing.T, a *app) map[string]any {
			planID, token := seedApplyPlan(t, a, "ghost-blueprint")
			return map[string]any{"name": "ghost-blueprint", "plan_id": planID, "confirm_token": token}
		}, nil)
	})

	t.Run("目标父目录不可解析", func(t *testing.T) {
		applyAuditCase(t, "denied", func(t *testing.T, a *app) map[string]any {
			planID, token := seedApplyPlan(t, a, "nginx-vhost")
			p := reseedPlan(t, a, planID)
			blocker := filepath.Join(a.outputDirs[0], "blocker")
			if err := os.WriteFile(blocker, []byte("我是文件不是目录"), 0o644); err != nil {
				t.Fatal(err)
			}
			p.Target = filepath.Join(blocker, "x.conf")
			a.plans.put(planID, p)
			return map[string]any{"name": "nginx-vhost", "plan_id": planID, "confirm_token": token}
		}, nil)
	})

	t.Run("写入配置失败", func(t *testing.T) {
		// 目标是一个已存在的空目录:符号链接门与白名单门都放行(父目录就是
		// outputDir 本身),写盘以 EISDIR 失败 —— root 与非 root 同果。
		applyAuditCase(t, "error", func(t *testing.T, a *app) map[string]any {
			planID, token := seedApplyPlan(t, a, "nginx-vhost")
			p := reseedPlan(t, a, planID)
			p.Target = filepath.Join(a.outputDirs[0], "a-dir")
			if err := os.Mkdir(p.Target, 0o755); err != nil {
				t.Fatal(err)
			}
			a.plans.put(planID, p)
			return map[string]any{"name": "nginx-vhost", "plan_id": planID, "confirm_token": token}
		}, nil)
	})

	t.Run("post_check 失败", func(t *testing.T) {
		applyAuditCase(t, "error", nil, func(name string, _ []string) error {
			if name == "nginx" {
				return errors.New("nginx -t 语法校验失败")
			}
			return nil
		})
	})

	t.Run("reload 失败", func(t *testing.T) {
		applyAuditCase(t, "error", nil, func(name string, args []string) error {
			if name == "systemctl" && len(args) > 0 && args[0] == "restart" {
				return errors.New("systemctl restart nginx 失败")
			}
			return nil
		})
	})
}

// TestAudit_RemoveOutcomeUsesSharedVocabulary 钉 blueprint_remove 的结局词表:
// 完成条目从 legacy "ok" 收敛为全仓一致的 success,拒绝记 denied。
func TestAudit_RemoveOutcomeUsesSharedVocabulary(t *testing.T) {
	t.Run("被拒记 denied", func(t *testing.T) {
		logPath := newAuditLog(t)
		a := newTestApp(t)
		session, ctx := connectServer(t, a)
		res, _ := callText(t, session, ctx, "blueprint_remove", map[string]any{
			"name": "no-such-blueprint", "plan_id": "p", "confirm_token": "t",
		})
		if !res.IsError {
			t.Fatal("未注册蓝图 remove 应被拒")
		}
		mustSingleEntry(t, logPath, "blueprint_remove", "denied")
	})

	t.Run("完成记 success 且带 config_path", func(t *testing.T) {
		logPath := newAuditLog(t)
		a := newTestApp(t)
		a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
		session, ctx := connectServer(t, a)
		planID, token := seedApplyPlan(t, a, "nginx-vhost")
		in := map[string]any{"name": "nginx-vhost", "plan_id": planID, "confirm_token": token}
		if res, text := callText(t, session, ctx, "blueprint_apply", in); res.IsError {
			t.Fatalf("前置 apply 失败: %s", text)
		}
		applied, ok := a.plans.get(planID)
		if !ok || applied.RemoveToken.Token == "" {
			t.Fatalf("apply 未生成 remove 令牌: %+v", applied)
		}
		// 两次调用两条目(apply success + remove success)。
		if res, text := callText(t, session, ctx, "blueprint_remove", map[string]any{
			"name": "nginx-vhost", "plan_id": planID, "confirm_token": applied.RemoveToken.Token,
		}); res.IsError {
			t.Fatalf("remove 失败: %s", text)
		}
		raw, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
		if len(lines) != 2 {
			t.Fatalf("apply+remove 应恰两条条目, 实得 %d:\n%s", len(lines), raw)
		}
		var e auditEntry
		if err := json.Unmarshal([]byte(lines[1]), &e); err != nil {
			t.Fatal(err)
		}
		if e.Tool != "blueprint_remove" || e.Outcome != "success" {
			t.Errorf("remove 条目结局漂移: %+v", e)
		}
		if e.Args["config_path"] == nil || e.Args["config_path"] == "" {
			t.Errorf("remove 成功条目应带 config_path: %v", e.Args)
		}
		if n, err := audit.Verify(logPath); err != nil || n != 2 {
			t.Errorf("audit.Verify = (%d, %v), want (2, nil)", n, err)
		}
	})
}

// TestAudit_RegisteredToolsAllCovered 结构性守门:tools/list 的每个工具都必须在
// 覆盖表里有一条被拒用例(新增工具未接 choke point 审计 → 这里直接红)。
func TestAudit_RegisteredToolsAllCovered(t *testing.T) {
	// tool -> 会被该工具拒绝的入参(各工具最外层校验门)。
	rejections := map[string]map[string]any{
		"blueprint_list":    {},
		"blueprint_inspect": {"name": "no-such-blueprint"},
		"blueprint_render":  {"name": "no-such-blueprint", "params": map[string]any{}},
		"blueprint_status":  {"name": "no-such-blueprint"},
		"blueprint_apply":   {"name": "nginx-vhost", "plan_id": "no-such-plan", "confirm_token": "t"},
		"blueprint_remove":  {"name": "no-such-blueprint", "plan_id": "p", "confirm_token": "t"},
	}

	logPath := newAuditLog(t)
	a := newTestApp(t)
	a.execCmd = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	session, ctx := connectServer(t, a)

	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	if len(listed.Tools) != len(rejections) {
		t.Fatalf("注册工具数 = %d,覆盖表 = %d(新增工具必须补审计用例)", len(listed.Tools), len(rejections))
	}

	// 逐工具比对:哈希链不可截断,故第 i 次调用后第 i 条必须属于第 i 个工具。
	seen := map[string]bool{}
	for i, tool := range listed.Tools {
		args, ok := rejections[tool.Name]
		if !ok {
			t.Fatalf("工具 %s 无审计覆盖用例(须在 handler choke point 落审计并补本表)", tool.Name)
		}
		seen[tool.Name] = true
		if _, text := callText(t, session, ctx, tool.Name, args); text == "" {
			t.Fatalf("工具 %s 无回包", tool.Name)
		}
		raw, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
		if len(lines) != i+1 {
			t.Fatalf("第 %d 次调用后审计条数 = %d(每次调用恰一条):\n%s", i+1, len(lines), raw)
		}
		var e auditEntry
		if err := json.Unmarshal([]byte(lines[i]), &e); err != nil {
			t.Fatal(err)
		}
		if e.Tool != tool.Name || e.Identity != blueprintIdentity {
			t.Errorf("第 %d 条条目漂移: %+v(want tool=%s)", i+1, e, tool.Name)
		}
		// blueprint_list 无入参且无拒绝门,成功调用记 success;其余为 denied。
		wantOutcome := "denied"
		if tool.Name == "blueprint_list" {
			wantOutcome = "success"
		}
		if e.Outcome != wantOutcome {
			t.Errorf("%s 条目结局 = %s, want %s(args=%v)", tool.Name, e.Outcome, wantOutcome, e.Args)
		}
	}
	for name := range rejections {
		if !seen[name] {
			t.Errorf("覆盖表里的 %s 未出现在 tools/list", name)
		}
	}
	if n, err := audit.Verify(logPath); err != nil || n != len(rejections) {
		t.Errorf("audit.Verify = (%d, %v), want (%d, nil)", n, err, len(rejections))
	}
}
