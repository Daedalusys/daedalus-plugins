package main

// apply_usage_path_test.go —— 用量账本的落点判定:账本不得落在用户 HOME 之下。
//
// HOME 下的文件属主就是跑 MCP 的用户,自己截断就能把 max_uses 归零(跨重启
// 可重置)。所以账本落在 HOME 之下 ⇒ fail-closed 拒绝,而不是"照常记账"。
//
// 残留语义:即便账本落在系统路径上,能写它的用户仍可以少记 —— 所以 max_uses
// 是速率限制,不是安全边界。真正的边界是作用域 + TTL + 签发者上限。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Daedalusys/daedalus-sdk/grant"
)

// 用量账本落在用户 HOME 之下 ⇒ 拒绝,码是 grant_usage_failed,且绝不执行。
func TestTxApplyRejectsUsageLedgerUnderHome(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261121-00000001", "systemd:user:restart:demo.service", 2, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, g)

	// 把 HOME 指到临时目录:判定只看"账本在不在 HOME 之下",与本机真实家目录无关。
	home := t.TempDir()
	t.Setenv("HOME", home)
	txDir := filepath.Join(home, ".local", "share", "daedalus", "tx")
	t.Setenv("DAEDALUS_TX_DIR", txDir)

	_, rej := txApply(signerConfig(t), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: g.ID,
	})
	if rej == nil || rej.Error != "grant_usage_failed" {
		t.Fatalf("期望 grant_usage_failed, 收到 %+v", rej)
	}
	if !strings.Contains(rej.Detail, "HOME") {
		t.Fatalf("拒绝理由必须点明用量账本落在 HOME 之下: %q", rej.Detail)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 用量账本不在 HOME 之下 ⇒ 正常消费条子、正常记账、正常执行。
func TestTxApplyAcceptsUsageLedgerOutsideHome(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261121-00000002", "systemd:user:restart:demo.service", 2, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, g)

	home := t.TempDir()
	t.Setenv("HOME", home)
	txDir := t.TempDir()
	if pathUnderDir(txDir, home) {
		t.Skipf("临时目录 %s 恰在 HOME %s 之下,本用例不成立", txDir, home)
	}
	t.Setenv("DAEDALUS_TX_DIR", txDir)

	view, rej := txApply(signerConfig(t), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: g.ID,
	})
	if rej != nil {
		t.Fatalf("HOME 之外的用量账本应放行, 收到拒绝 %+v", rej)
	}
	if view.Outcome != "applied" {
		t.Fatalf("view = %+v", view)
	}
	if _, err := os.Stat(filepath.Join(txDir, grant.UsageFileName)); err != nil {
		t.Fatalf("用量记账未落在指定目录: %v", err)
	}
}

// 路径判定本身:同前缀的兄弟目录不算 HOME 之下(/home/user2 不是 /home/user 的子目录)。
func TestPathUnderDirBoundary(t *testing.T) {
	cases := []struct {
		path string
		dir  string
		want bool
	}{
		{path: "/home/user/.local/share/daedalus/tx/grant-usage.jsonl", dir: "/home/user", want: true},
		{path: "/home/user", dir: "/home/user", want: true},
		{path: "/home/user2/tx", dir: "/home/user", want: false},
		{path: "/var/lib/daedalus/tx/grant-usage.jsonl", dir: "/home/user", want: false},
	}
	for _, c := range cases {
		if got := pathUnderDir(c.path, c.dir); got != c.want {
			t.Fatalf("pathUnderDir(%q, %q) = %v, 期望 %v", c.path, c.dir, got, c.want)
		}
	}
}
