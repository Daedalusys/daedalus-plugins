package main

// grants_test.go —— tx_grants 与拒绝体里的 available_grants。
//
// 条子目录对 agent 不可见,只靠人抄 id 的话,一张能用的条子等于不存在。所以
// 只读面必须回答「我手上有什么」:只列绑定到当前执行者的,过期的照列并标记,
// 坏文件单独进 invalid[] —— 一条坏文件不该挡住整张清单。

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func ptrUID(v uint32) *uint32 { return &v }

// 只列绑定到当前执行者的条子:文件属主是测试用户、执行者换成另一个 uid 时,
// 那张条子必须从清单里消失 —— 越权者连"它存在"都不该知道。
func TestTxGrantsListsOnlyExecutorBound(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	own := makeGrant("g-20261121-ffff0001", "systemd:user:restart:demo.service", 2, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, own)
	foreign := makeGrant("g-20261121-ffff0002", "systemd:user:restart:demo.service", 2, 30*time.Minute)
	foreign.ForUID = ptrUID(executorUID + 1)
	foreign.ForUser = "someone-else"
	writeGrantFile(t, f.grantsDir, foreign)

	usable, invalid, err := listUsableGrants()
	if err != nil {
		t.Fatalf("listUsableGrants: %v", err)
	}
	if len(invalid) != 0 {
		t.Fatalf("合法条子不该进 invalid: %+v", invalid)
	}
	if len(usable) != 1 || usable[0].ID != own.ID {
		t.Fatalf("清单 = %+v, 期望只含 %s", usable, own.ID)
	}

	// 换成另一个执行者:自己的条子立刻不可见(它属于原执行者)。
	swapExecutor(t, executorUID+1)
	usable, _, err = listUsableGrants()
	if err != nil {
		t.Fatalf("listUsableGrants: %v", err)
	}
	for _, b := range usable {
		if b.ID == own.ID {
			t.Fatalf("别人属主的条子出现在了清单里: %+v", b)
		}
	}
}

// 过期条子照列并标 expired;坏文件进 invalid[] 且不影响其他条目。
func TestTxGrantsReportsExpiredAndInvalid(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	valid := makeGrant("g-20261121-ffff0003", "systemd:user:restart:demo.service", 2, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, valid)
	expired := makeGrant("g-20261121-ffff0004", "systemd:user:restart:demo.service", 1, -30*time.Minute)
	writeGrantFile(t, f.grantsDir, expired)
	if err := os.WriteFile(filepath.Join(f.grantsDir, "g-broken.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	usable, invalid, err := listUsableGrants()
	if err != nil {
		t.Fatalf("listUsableGrants: %v", err)
	}
	if len(invalid) != 1 || invalid[0].File != "g-broken.json" {
		t.Fatalf("invalid = %+v, 期望只含 g-broken.json", invalid)
	}
	got := map[string]grantBrief{}
	for _, b := range usable {
		got[b.ID] = b
	}
	if b, ok := got[valid.ID]; !ok || b.Expired {
		t.Fatalf("有效条子缺失或被误标过期: %+v", got)
	}
	if b, ok := got[expired.ID]; !ok || !b.Expired {
		t.Fatalf("过期条子应照列并标 expired: %+v", got)
	}
}

// grant_required 拒绝体带 available_grants,且与 tx_grants 同一枚举源。
func TestGrantRequiredCarriesAvailableGrants(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261121-ffff0005", "systemd:user:restart:demo.service", 2, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, g)

	_, rej := txApply(signerConfig(t), applyIn{Kind: "service", Name: "demo.service", DesiredState: "restarted"})
	if rej == nil || rej.Error != codeGrantRequired {
		t.Fatalf("期望 %s, 收到 %+v", codeGrantRequired, rej)
	}
	view, serr := txGrants()
	if serr != nil {
		t.Fatalf("tx_grants: %+v", serr)
	}
	if len(rej.AvailableGrants) != 1 || !reflect.DeepEqual(rej.AvailableGrants, view.Grants) {
		t.Fatalf("available_grants = %+v, 期望与 tx_grants 一致: %+v", rej.AvailableGrants, view.Grants)
	}
}

// 传了别人的条子:拒绝体也带 available_grants,顺手告诉它该换成哪张。
func TestGrantForOtherUserCarriesAvailableGrants(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	own := makeGrant("g-20261121-ffff0006", "systemd:user:restart:demo.service", 2, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, own)
	foreign := makeGrant("g-20261121-ffff0007", "systemd:user:restart:demo.service", 2, 30*time.Minute)
	foreign.ForUID = ptrUID(executorUID + 1)
	foreign.ForUser = "someone-else"
	writeGrantFile(t, f.grantsDir, foreign)

	_, rej := txApply(signerConfig(t), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: foreign.ID,
	})
	if rej == nil || rej.Error != codeGrantForOtherUser {
		t.Fatalf("期望 %s, 收到 %+v", codeGrantForOtherUser, rej)
	}
	view, serr := txGrants()
	if serr != nil {
		t.Fatalf("tx_grants: %+v", serr)
	}
	if len(rej.AvailableGrants) != 1 || !reflect.DeepEqual(rej.AvailableGrants, view.Grants) {
		t.Fatalf("available_grants = %+v, 期望与 tx_grants 一致: %+v", rej.AvailableGrants, view.Grants)
	}
}
