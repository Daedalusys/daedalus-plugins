// main_test.go —— organize 的工具层单元测试。
//
// 复用 fs 的 testdata/policy.toml 策略 fixture(白名单收缩为仅 /tmp),
// 验证:
//   - 2 个只读工具(organize_plan / organize_preview)路径校验 + 分类正确性;
//   - 1 个写型工具(organize_apply)的 confirm_token 守门 + 越界拒绝;
//   - applyPolicy 在 corrupt 与 missing policy 下 fail-closed。
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const testPolicy = "testdata/policy.toml"

// setupTestAllowedDirs 把 pathguard 的 AllowedDirs 设为 testPolicy 的白名单,
// 模拟 applyPolicy() 的运行时入口;测试结束自动恢复。
func setupTestAllowedDirs(t *testing.T) {
	t.Helper()
	t.Setenv("DAEDALUS_POLICY_PATH", filepath.Join("testdata", "policy.toml"))
	if err := applyPolicy(); err != nil {
		t.Fatalf("applyPolicy 失败: %v", err)
	}
}

// mcpText 安全地从 MCP CallToolResult 提取文本(空结果返 "")。
func mcpText(res *mcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok && tc != nil {
		return tc.Text
	}
	return ""
}

// decodeJSON 把 MCP 文本载荷解码为 out;用于强类型断言测试输出字段。
func decodeJSON(t *testing.T, res *mcp.CallToolResult, out any) {
	t.Helper()
	if err := json.Unmarshal([]byte(mcpText(res)), out); err != nil {
		t.Fatalf("解析 JSON 失败: %v; 文本: %s", err, mcpText(res))
	}
}

// mustCreateFile 在 dir 下创建 name + content,跳过 nil 错误分支(t.Helper 内)。
func mustCreateFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
	return full
}

// setMTime 把 path 的 mtime 设置为给定时间(用于 by_date 测试)。
func setMTime(t *testing.T, path string, tm time.Time) {
	t.Helper()
	if err := os.Chtimes(path, tm, tm); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

// TestPlan_ByExt 验证 by_ext 规则按扩展名分目录:tmpdir 下建 .jpg/.pdf/.txt,
// plan 阶段 3 个 moves,每条 to 的父目录名等于扩展名(小写)。
func TestPlan_ByExt(t *testing.T) {
	setupTestAllowedDirs(t)
	tmp := t.TempDir()
	mustCreateFile(t, tmp, "a.jpg", []byte("jpg-bytes"))
	mustCreateFile(t, tmp, "b.pdf", []byte("pdf-bytes"))
	mustCreateFile(t, tmp, "c.txt", []byte("txt-bytes"))

	res, _, err := organizePlan(context.Background(), nil, OrganizePlanInput{
		SourceDir: tmp,
		Rule:      ruleByExt,
	})
	if err != nil {
		t.Fatalf("organizePlan 返 Go err: %v", err)
	}
	if res.IsError {
		t.Fatalf("organizePlan 意外错误: %s", mcpText(res))
	}
	var out planResult
	decodeJSON(t, res, &out)
	if len(out.Moves) != 3 {
		t.Fatalf("moves 应为 3,实得 %d: %+v", len(out.Moves), out.Moves)
	}
	wantDirs := map[string]bool{"jpg": true, "pdf": true, "txt": true}
	for _, m := range out.Moves {
		parent := filepath.Base(filepath.Dir(m.To))
		if !wantDirs[parent] {
			t.Errorf("move %s → %s: 父目录应为 jpg/pdf/txt 之一,实得 %q", m.From, m.To, parent)
		}
	}
	if out.ConfirmToken == "" {
		t.Error("confirm_token 应非空")
	}
	if !strings.HasPrefix(out.PlanID, "organize-") {
		t.Errorf("plan_id 形如 organize-<16hex>,实得 %q", out.PlanID)
	}
}

// TestPlan_ByDate 验证 by_date 规则按 mtime 年月分目录:2 个文件 mtime 跨
// 2024-01 与 2024-03,plan 阶段 2 个 moves,dir_name = "YYYY/YYYY-MM"。
func TestPlan_ByDate(t *testing.T) {
	setupTestAllowedDirs(t)
	tmp := t.TempDir()
	p1 := mustCreateFile(t, tmp, "winter.dat", []byte("x"))
	p2 := mustCreateFile(t, tmp, "spring.dat", []byte("y"))
	setMTime(t, p1, time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC))
	setMTime(t, p2, time.Date(2024, 3, 20, 0, 0, 0, 0, time.UTC))

	res, _, err := organizePlan(context.Background(), nil, OrganizePlanInput{
		SourceDir: tmp,
		Rule:      ruleByDate,
	})
	if err != nil {
		t.Fatalf("organizePlan 返 Go err: %v", err)
	}
	if res.IsError {
		t.Fatalf("organizePlan 意外错误: %s", mcpText(res))
	}
	var out planResult
	decodeJSON(t, res, &out)
	if len(out.Moves) != 2 {
		t.Fatalf("moves 应为 2,实得 %d", len(out.Moves))
	}
	wantDirs := map[string]bool{"2024/2024-01": true, "2024/2024-03": true}
	for _, m := range out.Moves {
		rel, err := filepath.Rel(tmp, filepath.Dir(m.To))
		if err != nil {
			t.Fatalf("rel %s: %v", m.To, err)
		}
		if !wantDirs[rel] {
			t.Errorf("move %s → %s: 父目录应为 2024/2024-01 或 2024/2024-03,实得 %q", m.From, m.To, rel)
		}
	}
}

// TestPreview_RenameConflict 预创建目标 jpg/a.jpg,plan 后 preview 选 rename
// 策略,期望 to 被改写为 ".../a (1).jpg"。
func TestPreview_RenameConflict(t *testing.T) {
	setupTestAllowedDirs(t)
	tmp := t.TempDir()
	mustCreateFile(t, tmp, "a.jpg", []byte("orig"))
	// 预创建冲突目标(模拟磁盘上已存在同名文件)。
	if err := os.MkdirAll(filepath.Join(tmp, "jpg"), 0o755); err != nil {
		t.Fatalf("mkdir jpg: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "jpg", "a.jpg"), []byte("exists"), 0o644); err != nil {
		t.Fatalf("预创建冲突文件: %v", err)
	}

	res, _, err := organizePlan(context.Background(), nil, OrganizePlanInput{
		SourceDir: tmp,
		Rule:      ruleByExt,
	})
	if err != nil || res.IsError {
		t.Fatalf("organizePlan 失败: %v / %s", err, mcpText(res))
	}
	var planOut planResult
	decodeJSON(t, res, &planOut)

	pvRes, _, err := organizePreview(context.Background(), nil, OrganizePreviewInput{
		PlanID:           planOut.PlanID,
		ConflictStrategy: strategyRename,
	})
	if err != nil || pvRes.IsError {
		t.Fatalf("organizePreview 失败: %v / %s", err, mcpText(pvRes))
	}
	var pvOut previewResult
	decodeJSON(t, pvRes, &pvOut)
	if pvOut.Status != "ok" {
		t.Fatalf("preview status 应为 ok,实得 %q", pvOut.Status)
	}
	if len(pvOut.FinalMoves) != 1 {
		t.Fatalf("final_moves 应为 1,实得 %d", len(pvOut.FinalMoves))
	}
	to := pvOut.FinalMoves[0].To
	if !strings.HasSuffix(to, "a (1).jpg") {
		t.Errorf("rename 后 to 应以 'a (1).jpg' 结尾,实得 %s", to)
	}
}

// TestPreview_Abort 选 abort 策略,期望 status=aborted 且不返回 final_moves。
func TestPreview_Abort(t *testing.T) {
	setupTestAllowedDirs(t)
	tmp := t.TempDir()
	mustCreateFile(t, tmp, "a.jpg", []byte("x"))

	res, _, err := organizePlan(context.Background(), nil, OrganizePlanInput{
		SourceDir: tmp,
		Rule:      ruleByExt,
	})
	if err != nil || res.IsError {
		t.Fatalf("organizePlan 失败: %v / %s", err, mcpText(res))
	}
	var planOut planResult
	decodeJSON(t, res, &planOut)

	pvRes, _, err := organizePreview(context.Background(), nil, OrganizePreviewInput{
		PlanID:           planOut.PlanID,
		ConflictStrategy: strategyAbort,
	})
	if err != nil || pvRes.IsError {
		t.Fatalf("organizePreview 失败: %v / %s", err, mcpText(pvRes))
	}
	var pvOut previewResult
	decodeJSON(t, pvRes, &pvOut)
	if pvOut.Status != "aborted" {
		t.Errorf("status 应为 aborted,实得 %q (reason=%q)", pvOut.Status, pvOut.Reason)
	}
	if len(pvOut.FinalMoves) != 0 {
		t.Errorf("aborted 时 final_moves 应为空,实得 %d 条", len(pvOut.FinalMoves))
	}
}

// TestApply_RequiresValidToken 验证缺 token / 伪造 token 都被拒绝。
func TestApply_RequiresValidToken(t *testing.T) {
	setupTestAllowedDirs(t)
	ctx := context.Background()

	// 缺 plan_id + token。
	res, _, err := organizeApply(ctx, nil, OrganizeApplyInput{
		ConflictStrategy: strategyRename,
	})
	if err != nil {
		t.Fatalf("organizeApply 返 Go err: %v", err)
	}
	if !res.IsError {
		t.Fatal("organizeApply 应在缺 token 时返 IsError")
	}

	// 伪造 token(plan_id 随意,token 没经过 GenerateConfirmToken 登记)。
	res, _, err = organizeApply(ctx, nil, OrganizeApplyInput{
		PlanID:           "plan-forged-organize",
		ConfirmToken:     "deadbeef-not-issued",
		ConflictStrategy: strategyRename,
	})
	if err != nil {
		t.Fatalf("organizeApply 返 Go err: %v", err)
	}
	if !res.IsError {
		t.Fatal("organizeApply 应在伪造 token 时返 IsError")
	}
	if !strings.Contains(mcpText(res), "confirm_token") {
		t.Errorf("错误消息应提及 confirm_token: %s", mcpText(res))
	}
}

// TestApply_OutOfAllowedDirs 验证 source_dir 不在白名单(/etc)时 pathguard
// 在 plan 阶段就拒绝,IsError 触发。
func TestApply_OutOfAllowedDirs(t *testing.T) {
	setupTestAllowedDirs(t)
	res, _, err := organizePlan(context.Background(), nil, OrganizePlanInput{
		SourceDir: "/etc",
		Rule:      ruleByType,
	})
	if err != nil {
		t.Fatalf("organizePlan 返 Go err: %v", err)
	}
	if !res.IsError {
		t.Fatal("organizePlan 应在 /etc 越界时返 IsError")
	}
	if !strings.Contains(mcpText(res), "outside") && !strings.Contains(mcpText(res), "denied") {
		t.Errorf("错误消息应提示白名单拒绝: %s", mcpText(res))
	}
}

// TestApplyPolicy_Corrupt 验证 applyPolicy 在 corrupt.toml 下 fail-closed。
func TestApplyPolicy_Corrupt(t *testing.T) {
	t.Setenv("DAEDALUS_POLICY_PATH", filepath.Join("testdata", "corrupt.toml"))
	if err := applyPolicy(); err == nil {
		t.Fatal("applyPolicy 应在 corrupt policy 下拒绝启动")
	}
}

// TestApplyPolicy_Missing 验证 applyPolicy 在指向不存在路径时 fail-closed。
func TestApplyPolicy_Missing(t *testing.T) {
	t.Setenv("DAEDALUS_POLICY_PATH", filepath.Join(t.TempDir(), "no-such-policy.toml"))
	if err := applyPolicy(); err == nil {
		t.Fatal("applyPolicy 应在缺失 policy 时 fail-closed")
	}
}
