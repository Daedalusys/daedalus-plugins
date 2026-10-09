// main_test.go —— diskclean 的工具层单元测试。
//
// 镜像 dupe 的 testdata/policy.toml 复用策略 fixture,验证:
//   - 3 个只读工具(disk_scan / disk_estimate / disk_explain)路径校验 + 输出形态;
//   - 1 个写型工具(disk_clean)的 confirm_token + pathguard.ValidateWritePath 守门;
//   - applyPolicy 在 corrupt 与 missing policy 下 fail-closed。
package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/confirmation"
	"github.com/Daedalusys/daedalus-sdk/pathguard"
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
	t.Cleanup(func() {
		pathguard.WithAllowedDirs([]string{"/home", "/var/log", "/tmp"})
	})
}

// mcpText 安全地从 MCP CallToolResult 提取文本(空结果返 "")。
func mcpText(res *mcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

// TestDiskScan_FindsFilesUnderTmp 验证 disk_scan 在 tmpdir 下能列出文件
// (tmpdir 路径在白名单 /tmp 下,但 classifyPath 会归 user_cache)。
func TestDiskScan_FindsFilesUnderTmp(t *testing.T) {
	setupTestAllowedDirs(t)
	tmp := t.TempDir()
	for i := 0; i < 3; i++ {
		p := filepath.Join(tmp, "file-"+string(rune('a'+i)))
		if err := os.WriteFile(p, []byte("0123456789"), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	res, _, err := diskScan(context.Background(), nil, DiskScanInput{
		Paths: []string{tmp},
		TopN:  10,
	})
	if err != nil {
		t.Fatalf("diskScan: %v", err)
	}
	if res.IsError {
		t.Fatalf("diskScan 意外错误: %s", mcpText(res))
	}
	text := mcpText(res)
	if !strings.Contains(text, `"items"`) {
		t.Errorf("输出缺 items 字段: %s", text)
	}
}

// TestDiskScan_PathGuardRejects 验证不在白名单的路径被 pathguard 拒绝。
func TestDiskScan_PathGuardRejects(t *testing.T) {
	setupTestAllowedDirs(t)
	res, _, err := diskScan(context.Background(), nil, DiskScanInput{
		Paths: []string{"/etc/shadow"},
	})
	if err != nil {
		t.Fatalf("diskScan 返 Go err: %v", err)
	}
	if !res.IsError {
		t.Fatalf("diskScan 应拒绝 /etc/shadow,但返回成功")
	}
}

// TestDiskExplain_TmpPathClassifies 验证 disk_explain 对 /tmp 下路径返回
// category=user_cache 且 what/risk_reason/what_if_deleted 非空(/tmp 是
// testdata fixture 的唯一 allowlist 目录,确保跨环境可跑)。
func TestDiskExplain_TmpPathClassifies(t *testing.T) {
	setupTestAllowedDirs(t)
	res, _, err := diskExplain(context.Background(), nil, DiskExplainInput{Path: "/tmp"})
	if err != nil {
		t.Fatalf("diskExplain: %v", err)
	}
	if res.IsError {
		t.Fatalf("diskExplain 意外错误: %s", mcpText(res))
	}
	text := mcpText(res)
	if !strings.Contains(text, `"category"`) {
		t.Errorf("explain 输出缺 category 字段: %s", text)
	}
	if !strings.Contains(text, `"what"`) {
		t.Errorf("explain 输出缺 what 字段: %s", text)
	}
}

// TestDiskClean_RequiresValidToken 验证 disk_clean 在缺 token / 伪造 token 时
// 被 confirmation.VerifyConfirmToken 拒绝并返 IsError 结果。
func TestDiskClean_RequiresValidToken(t *testing.T) {
	setupTestAllowedDirs(t)
	ctx := context.Background()

	// 缺 plan_id + token。
	res, _, err := diskClean(ctx, nil, DiskCleanInput{Paths: []string{"/tmp/x"}})
	if err != nil {
		t.Fatalf("diskClean 返 Go err: %v", err)
	}
	if !res.IsError {
		t.Fatal("diskClean 应在缺 token 时返 IsError")
	}

	// 伪造 token。
	res, _, err = diskClean(ctx, nil, DiskCleanInput{
		PlanID:       "plan-forged",
		ConfirmToken: "deadbeef-not-issued",
		Paths:        []string{"/tmp/x"},
	})
	if err != nil {
		t.Fatalf("diskClean 返 Go err: %v", err)
	}
	if !res.IsError {
		t.Fatal("diskClean 应在伪造 token 时返 IsError")
	}
	if !strings.Contains(mcpText(res), "confirm_token") {
		t.Errorf("错误消息应提及 confirm_token: %s", mcpText(res))
	}
}

// TestDiskClean_ValidatesTokenButRejectsWritePath 验证 confirm_token 通过后,
// 写二档(pathguard.ValidateWritePath)拒绝 /etc/shadow → IsError。
func TestDiskClean_ValidatesTokenButRejectsWritePath(t *testing.T) {
	setupTestAllowedDirs(t)
	ctx := context.Background()

	planID := "plan-write-test"
	tok := confirmation.GenerateConfirmToken(planID)

	res, _, err := diskClean(ctx, nil, DiskCleanInput{
		PlanID:       planID,
		ConfirmToken: tok.Token,
		Paths:        []string{"/etc/shadow"},
	})
	if err != nil {
		t.Fatalf("diskClean 返 Go err: %v", err)
	}
	if !res.IsError {
		t.Fatal("diskClean 应在写二档拒绝时返 IsError")
	}
	if !strings.Contains(mcpText(res), "写二档") {
		t.Errorf("错误消息应提及写二档拒绝: %s", mcpText(res))
	}
}

// TestDiskClean_NonexistentTarget 验证写二档对不存在的目标拒绝(强制完整
// realpath:目标不存在 → EvalSymlinks 失败 → 拒绝)。
func TestDiskClean_NonexistentTarget(t *testing.T) {
	setupTestAllowedDirs(t)
	ctx := context.Background()

	planID := "plan-missing-target"
	tok := confirmation.GenerateConfirmToken(planID)

	res, _, err := diskClean(ctx, nil, DiskCleanInput{
		PlanID:       planID,
		ConfirmToken: tok.Token,
		Paths:        []string{"/tmp/diskclean-missing-target-zzz/file.txt"},
	})
	if err != nil {
		t.Fatalf("diskClean 返 Go err: %v", err)
	}
	if !res.IsError {
		t.Fatal("diskClean 应在写二档 EvalSymlinks 失败时返 IsError")
	}
}

// TestApplyPolicy_Corrupt 验证 applyPolicy 在 corrupt.toml 下 fail-closed。
func TestApplyPolicy_Corrupt(t *testing.T) {
	t.Setenv("DAEDALUS_POLICY_PATH", filepath.Join("testdata", "corrupt.toml"))
	err := applyPolicy()
	if err == nil {
		t.Fatal("applyPolicy 应在 corrupt policy 下拒绝启动")
	}
}

// TestApplyPolicy_Missing 验证 applyPolicy 在显式指向不存在路径时 fail-closed。
func TestApplyPolicy_Missing(t *testing.T) {
	t.Setenv("DAEDALUS_POLICY_PATH", filepath.Join(t.TempDir(), "no-such-policy.toml"))
	err := applyPolicy()
	if err == nil {
		t.Fatal("applyPolicy 应在缺失 policy 时 fail-closed")
	}
}

// TestDiskScan_RespectsCategoriesFilter 验证 categories 过滤生效:仅传入
// journal 时,非 journal 类别的条目被排除。
func TestDiskScan_RespectsCategoriesFilter(t *testing.T) {
	setupTestAllowedDirs(t)
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "x"), []byte("hi"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, _, err := diskScan(context.Background(), nil, DiskScanInput{
		Paths:      []string{tmp},
		Categories: []string{categoryJournal},
		TopN:       10,
	})
	if err != nil {
		t.Fatalf("diskScan: %v", err)
	}
	if res.IsError {
		t.Fatalf("diskScan 意外错误: %s", mcpText(res))
	}
	if !strings.Contains(mcpText(res), `"items": []`) {
		t.Errorf("categories 过滤后应为空 items 列表,实得: %s", mcpText(res))
	}
}
