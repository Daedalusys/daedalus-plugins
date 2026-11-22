package main

// apply_pending_test.go —— 待办按人分目录:写进自己的目录,属主不对就 fail-closed。
//
// 待办里是本人要执行的 argv。所有本地用户共用一个 1777 目录时,别人读得到、
// 也抢建得了同名文件(粘滞位只挡删除/改名,不挡"我先建一个")。按人分目录
// 并在用之前核对属主,这两条都不再成立。
//
// 非 root 测试进程造不出"别人的目录"(chown 需要特权),所以"属主不符"一律
// 用 uid 参数与真实属主的错位来复现:目录是当前身份建的,而要求的是另一个 uid。

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Daedalusys/daedalus-sdk/pending"
)

// samplePending 造一份形态合法的待办:落盘用例只关心"写到了哪里",内容由
// SDK 的契约约束,这里不重复它的严格性用例。
func samplePending() pending.Pending {
	now := time.Now().UTC().Truncate(time.Second)
	return pending.Pending{
		ID:           "p-0123456789abcdef",
		Kind:         kindService,
		Name:         "demo.service",
		DesiredState: "restarted",
		Argv:         []string{"systemctl", "--user", "restart", "demo.service"},
		Scope:        "systemd:user:restart:demo.service",
		Reason:       "tier=human (deny)",
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Hour),
	}
}

// uidDirName 是 <根> 下某个执行者的子目录名,与生产口径一致:uid 的十进制串。
func uidDirName(uid uint32) string {
	return strconv.FormatUint(uint64(uid), 10)
}

// userPendingDir 只算路径不建目录:待办目录由被测的写入路径自己建,
// 夹具提前建好就测不到"不存在 ⇒ 建 0700"这条分支了。
func userPendingDir(root string) string {
	return filepath.Join(root, uidDirName(executorUID))
}

// ownerOf 取路径的 stat 属主 uid,判定不了就直接失败。
func ownerOf(t *testing.T, path string) uint32 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("无法取 %s 的属主", path)
	}
	return stat.Uid
}

// 待办必须落在 <根>/<执行者 uid>/<id>.json,目录由写入路径建出来且是 0700、
// 属主是执行者自己 —— 这三条同时成立,才谈得上"别人读不到也塞不进"。
func TestWritePendingGoesToUserDir(t *testing.T) {
	root := t.TempDir()
	t.Setenv(envPendingDir, root)
	doc := samplePending()

	if err := writePending(doc); err != nil {
		t.Fatalf("写待办失败: %v", err)
	}

	dir := userPendingDir(root)
	if got := ownerOf(t, dir); got != executorUID {
		t.Fatalf("待办目录属主 = %d, 期望 %d", got, executorUID)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("待办目录模式 = %o, 期望 0700", perm)
	}

	path := filepath.Join(dir, doc.ID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("待办未落在 %s: %v", path, err)
	}
	// 文件权限与今天一致:同机 root 与本人可读。
	if fi, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	} else if perm := fi.Mode().Perm(); perm != 0o644 {
		t.Fatalf("待办文件模式 = %o, 期望 0644", perm)
	}

	parsed, err := pending.ParsePending(data)
	if err != nil {
		t.Fatalf("落盘的待办不合线上契约: %v", err)
	}
	if parsed.ID != doc.ID || !parsed.CreatedAt.Equal(doc.CreatedAt) || !parsed.ExpiresAt.Equal(doc.ExpiresAt) {
		t.Fatalf("落盘的待办 = %+v, 期望 %+v", parsed, doc)
	}

	// 根目录里不许再出现直落的待办文件:那些文件对同机所有用户可读。
	if _, err := os.Lstat(filepath.Join(root, doc.ID+".json")); !os.IsNotExist(err) {
		t.Fatalf("待办落在了根目录(stat err=%v)", err)
	}
}

// 目录已存在但属主不是要求的那个人 ⇒ 拒绝,且不许接管、不许 chmod:
// 别人拥有的目录里,别人随时能塞文件,"这份待办是本人出的"就不再成立。
func TestEnsureUserDirFailsClosedOnForeignOwner(t *testing.T) {
	root := t.TempDir()
	// 目录由当前身份建;随后要求它属于另一个 uid —— 这就是"别人的目录"的复现。
	foreign := filepath.Join(root, uidDirName(uint32(os.Geteuid())+1))
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	beforeOwner := ownerOf(t, foreign)
	beforeInfo, err := os.Lstat(foreign)
	if err != nil {
		t.Fatal(err)
	}

	err = ensureUserDir(foreign, uint32(os.Geteuid())+1)
	if err == nil {
		t.Fatal("属主不符必须 fail-closed")
	}
	// 错误串要给出可照抄的处置:管理员删掉目录后重试。
	if !strings.Contains(err.Error(), "sudo rm -rf "+foreign) {
		t.Fatalf("错误串应给出处置步骤: %v", err)
	}

	if got := ownerOf(t, foreign); got != beforeOwner {
		t.Fatalf("目录属主被改动了: %d → %d", beforeOwner, got)
	}
	afterInfo, err := os.Lstat(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if afterInfo.Mode().Perm() != beforeInfo.Mode().Perm() {
		t.Fatalf("目录模式被改动了: %o → %o", beforeInfo.Mode().Perm(), afterInfo.Mode().Perm())
	}
}

// 同一个前提走到 writePending:必须失败,不许"换个地方静默写下去"。
func TestWritePendingFailsWhenUserDirForeign(t *testing.T) {
	root := t.TempDir()
	t.Setenv(envPendingDir, root)
	// 换个执行者身份,让 <根>/<该 uid> 成为"别人的目录"(目录由当前身份建)。
	swapExecutor(t, executorUID+1)
	dir := userPendingDir(root)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	doc := samplePending()

	err := writePending(doc)
	if err == nil {
		t.Fatal("待办目录属主不符时写待办必须失败")
	}
	if !strings.Contains(err.Error(), "sudo rm -rf "+dir) {
		t.Fatalf("错误串应给出处置步骤: %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(dir, doc.ID+".json")); !os.IsNotExist(statErr) {
		t.Fatalf("待办被静默写进了别人的目录(stat err=%v)", statErr)
	}
	// 也不许退回根目录去写。
	if _, statErr := os.Lstat(filepath.Join(root, doc.ID+".json")); !os.IsNotExist(statErr) {
		t.Fatalf("待办被静默写到了根目录(stat err=%v)", statErr)
	}
}
