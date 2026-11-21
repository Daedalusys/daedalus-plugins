package main

// apply_executor_test.go —— 消费侧认执行者:条子绑定、账本按人、待办带人。
//
// 条子文件属主 = 签发者,但"谁能用"是另一个问题:同一台机器上多个用户的助手
// 共享条子目录,不认执行者的话,root 给 A 签的条子 B 也能花。这里把执行者身份
// 钉进三处:条子绑定(BindExecutor)、用量账本文件名、待办 id 派生。

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
	"github.com/Daedalusys/daedalus-sdk/grant"
)

// swapExecutor 临时把执行者 uid 换成另一个身份;用例结束恢复。
// 非 root 测试进程造不出"别人的文件",所以越权场景只能靠换执行者来复现。
func swapExecutor(t *testing.T, uid uint32) {
	t.Helper()
	old := executorUID
	executorUID = uid
	t.Cleanup(func() { executorUID = old })
}

// 条子属主是测试用户,执行者换成另一个 uid ⇒ 拒绝且码是 grant_for_other_user。
// 这就是真机上"B 的助手拿 A 的条子"的单元级复现。
func TestConsumeGrantRejectsOtherExecutor(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261121-eeee0001", "systemd:user:restart:demo.service", 2, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, g)

	swapExecutor(t, executorUID+1)
	scope, err := autonomy.ParseScope("systemd:user:restart:demo.service")
	if err != nil {
		t.Fatal(err)
	}
	rej := consumeGrant(signerConfig(t), g.ID, scope, time.Now())
	if rej == nil || rej.Error != codeGrantForOtherUser {
		t.Fatalf("期望 %s, 收到 %+v", codeGrantForOtherUser, rej)
	}
}

// 同一张条子,执行者 = 属主 ⇒ 通过:自己的条子自己用,不能被绑定判定误伤。
func TestConsumeGrantAllowsOwnerExecutor(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261121-eeee0002", "systemd:user:restart:demo.service", 2, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, g)

	scope, err := autonomy.ParseScope("systemd:user:restart:demo.service")
	if err != nil {
		t.Fatal(err)
	}
	if rej := consumeGrant(signerConfig(t), g.ID, scope, time.Now()); rej != nil {
		t.Fatalf("自己的条子应放行, 收到 %+v", rej)
	}
}

// 账本文件名带执行者 uid:记账必须写进 usage-<执行者>.jsonl,而不是任何别的文件。
// 全节点共用一个账本时,第一个创建者拥有它,第二个用户永远打不开 —— 账本必须按人分。
func TestUsageLedgerNamedByExecutor(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	oldUID := executorUID
	uid := oldUID + 77
	swapExecutor(t, uid)

	if err := grantUsage.consume("g-20261121-eeee0003", 2, time.Now()); err != nil {
		t.Fatalf("记账失败: %v", err)
	}

	want := filepath.Join(f.txDir, grant.UsageFileNameFor(uid))
	data, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("记账未落在 %s: %v", want, err)
	}
	if len(data) == 0 {
		t.Fatalf("%s 为空", want)
	}
	// 原身份的账本不得被写:文件名必须真的跟着执行者走。
	if _, err := os.Stat(filepath.Join(f.txDir, grant.UsageFileNameFor(oldUID))); !os.IsNotExist(err) {
		t.Fatalf("记账写进了别人的账本(stat err=%v)", err)
	}
}

// 同一意图 + 两个不同执行者 ⇒ 两个不同待办 id:否则 root 批一份,两个人的
// 助手都能拿去用。
func TestPendingIDDiffersPerExecutor(t *testing.T) {
	a := pendingIDFor("service", "demo.service", "restarted", "systemd:user:restart:demo.service", 1000)
	b := pendingIDFor("service", "demo.service", "restarted", "systemd:user:restart:demo.service", 1001)
	if a == b {
		t.Fatalf("不同执行者撞了同一个待办 id: %s", a)
	}
}

// 同一意图 + 同一执行者 ⇒ 稳定复现同一个 id:确定性丢了,AI 第二次调用就找不到
// 人批准过的那一条。
func TestPendingIDStablePerExecutor(t *testing.T) {
	args := []string{"service", "demo.service", "restarted", "systemd:user:restart:demo.service"}
	first := pendingIDFor(args[0], args[1], args[2], args[3], 1000)
	second := pendingIDFor(args[0], args[1], args[2], args[3], 1000)
	if first != second {
		t.Fatalf("同一意图 + 同一执行者 id 不稳定: %s != %s", first, second)
	}
}
