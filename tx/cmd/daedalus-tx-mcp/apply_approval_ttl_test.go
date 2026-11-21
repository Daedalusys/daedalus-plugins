package main

// apply_approval_ttl_test.go —— 人批准的新鲜度窗口:批准不是长期通行证。
//
// 批准绑定的是"这一小段时间内准你做这一件事":approved_at + 窗口 > now 才算数。
// 窗口过了就作废,重新申请、重新批 —— 半夜批的"这一次"不该留到明天当无限次
// 重放的凭据。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeApprovalAt 落一条带指定批准时刻的批准记录:形状与 daedalus-tx approve
// 逐字一致,只有 approved_at 可控 —— 新鲜度用例要能钉住"批了多久算数"。
func writeApprovalAt(t *testing.T, dir, id, argvSHA, approvedBy string, approvedAt time.Time) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := map[string]string{
		"id":          id,
		"argv_sha256": argvSHA,
		"approved_by": approvedBy,
		"approved_at": approvedAt.UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// approvalFixture 走到"待办已出、待批准"这一步,返回待办 id 与被批准的 argv。
func approvalFixture(t *testing.T) (string, []string) {
	t.Helper()
	argv := []string{"systemctl", "--user", "start", "demo.service"}
	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.PendingID == "" {
		t.Fatalf("第一次调用应出待办: %+v", rej)
	}
	return rej.PendingID, argv
}

// 新鲜度窗口:过期 ⇒ 拒绝(单独一个码 approval_stale),窗口内 ⇒ 照常执行。
// 窗口边界取"窗口内一分钟"(59 分钟前批准仍算数),以及恰好等于窗口的那一刻。
func TestTxApplyApprovalFreshnessWindow(t *testing.T) {
	cases := []struct {
		name       string
		approvedAt time.Duration
		wantStale  bool
	}{
		{name: "两小时前批准已过期", approvedAt: 2 * time.Hour, wantStale: true},
		{name: "窗口边界内侧仍有效", approvedAt: 59 * time.Minute, wantStale: false},
		{name: "三十分钟前批准有效", approvedAt: 30 * time.Minute, wantStale: false},
		{name: "恰好等于窗口即过期", approvedAt: time.Hour, wantStale: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newApplyFixture(t, obsUnknown)
			pendingID, argv := approvalFixture(t)
			writeApprovalAt(t, f.approvals, pendingID, testArgvSHA256(argv), "root", time.Now().Add(-c.approvedAt))

			_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
			if c.wantStale {
				if rej == nil || rej.Error != "approval_stale" {
					t.Fatalf("期望 approval_stale, 收到 %+v", rej)
				}
				// 过期不是"没批准":绝不执行,也不许悄悄换成"需要人批准"。
				requireNoChanges(t, readCalls(t, f.calls))
				lines := readAuditLines(t, f.auditLog)
				last := lines[len(lines)-1]
				if last.Outcome != "denied" || last.Args["error"] != "approval_stale" {
					t.Fatalf("过期批准必须落 denied 审计: %+v", last)
				}
				return
			}
			if rej != nil {
				t.Fatalf("窗口内的批准应执行, 收到拒绝 %+v", rej)
			}
			if got := appliedIn(t, readCalls(t, f.calls)); got != 1 {
				t.Fatalf("apply 应被调用一次, 实际 %d 次", got)
			}
		})
	}
}

// 新鲜度窗口可用环境变量覆盖;空值视为未设置(回落到默认窗口),不是"零窗口"。
func TestTxApplyApprovalFreshnessWindowEnvOverride(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	pendingID, argv := approvalFixture(t)

	// 窗口收到 10 分钟:20 分钟前批准的记录必须过期。
	t.Setenv(envApprovalTTL, "10m")
	writeApprovalAt(t, f.approvals, pendingID, testArgvSHA256(argv), "root", time.Now().Add(-20*time.Minute))
	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.Error != "approval_stale" {
		t.Fatalf("窗口 10m 下 20 分钟前的批准应过期, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))

	// 空值视为未设置:回落到默认窗口(1 小时),同样的批准仍然有效。
	t.Setenv(envApprovalTTL, "")
	f2 := newApplyFixture(t, obsUnknown)
	pendingID2, argv2 := approvalFixture(t)
	writeApprovalAt(t, f2.approvals, pendingID2, testArgvSHA256(argv2), "root", time.Now().Add(-30*time.Minute))
	if _, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"}); rej != nil {
		t.Fatalf("空覆盖值应回落到默认窗口, 收到拒绝 %+v", rej)
	}
}

// 覆盖值写坏 ⇒ fail-closed:窗口不可解析就不许执行,而不是把窗口当成无限大。
func TestTxApplyApprovalFreshnessWindowInvalidEnvIsRejected(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	pendingID, argv := approvalFixture(t)
	t.Setenv(envApprovalTTL, "不是时长")
	writeApprovalAt(t, f.approvals, pendingID, testArgvSHA256(argv), "root", time.Now())

	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.Error != "approval_stale" {
		t.Fatalf("期望 approval_stale, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}
