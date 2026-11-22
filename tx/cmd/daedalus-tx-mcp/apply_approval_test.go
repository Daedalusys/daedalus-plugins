package main

// apply_approval_test.go —— 批准的两道门:批给谁、能用几次。
//
// 指纹挡的是"批的与跑的不是同一条命令",请求者挡的是"批的不是你的请求"。少了
// 后一道,别人在同一 id 上放的待办被批之后,本人指纹对得上就执行了 —— 批准成了
// 一条无主的 argv。第三道是消费标记:一份批准只能用一次,重放必须与"改了命令"
// 分得开,否则客户端不知道该怎么补救。
//
// 非 root 测试进程造不出"别人的目录/别人的请求",所以两处越权都用身份错位复现:
// 执行者换一个 uid,而磁盘上的属主/批准记录里的请求者仍是原身份。

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// pendingFromApply 走一次 tx_apply 拿到确定性的待办 id(AI 出待办那一步)。
func pendingFromApply(t *testing.T) string {
	t.Helper()
	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.PendingID == "" {
		t.Fatalf("第一次调用应出待办: %+v", rej)
	}
	return rej.PendingID
}

// writeApprovalRecord 落一条批准记录,请求者 uid 由调用方指定 —— 它决定"批给谁",
// 其余形状与 daedalus-tx approve 逐字一致。
func writeApprovalRecord(t *testing.T, dir, id, argvSHA string, requestedByUID uint32, approvedAt time.Time) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := map[string]any{
		"id":               id,
		"argv_sha256":      argvSHA,
		"requested_by_uid": requestedByUID,
		"approved_by":      "root",
		"approved_at":      approvedAt.UTC().Format(time.RFC3339),
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

// 批给别人的批准不能执行:即使 argv 逐字相同、指纹对得上。
// 这条门独立于指纹 —— 指纹能挡住"改了命令",挡不住"命令一样但不是批给你的"。
func TestApprovalForOtherUserRejected(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	argv := []string{"systemctl", "--user", "start", "demo.service"}
	pendingID := pendingFromApply(t)
	// 批准记录批的是另一个执行者的请求,而本次执行者是测试身份。
	writeApprovalRecord(t, f.approvals, pendingID, testArgvSHA256(argv), executorUID+1, time.Now())
	// 先清掉这份待办:"没被批过"的请求再来一次会重新落盘,正好用来证明下面
	// 这条拒绝没有退化成"重新出待办"。
	if err := os.Remove(filepath.Join(userPendingDir(f.pending), pendingID+".json")); err != nil {
		t.Fatal(err)
	}

	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.Error != codeApprovalForOtherUser {
		t.Fatalf("期望 %s, 收到 %+v", codeApprovalForOtherUser, rej)
	}
	// 拒绝理由必须点明批的是谁:审批的人与 agent 都要看出"这不是我的"。
	if !strings.Contains(rej.Detail, "不是你的") {
		t.Fatalf("理由应点明请求者不是本人: %q", rej.Detail)
	}
	requireNoChanges(t, readCalls(t, f.calls))
	// 别人被批过 = 本人还没被批过:不许退化成"重新出待办",也不许烧掉消费标记。
	requireNoPending(t, f.pending)
	if entries, err := os.ReadDir(consumedDirFor(executorUID)); err == nil && len(entries) != 0 {
		t.Fatalf("请求者不符不该消费批准: %v", entries)
	}
	lines := readAuditLines(t, f.auditLog)
	last := lines[len(lines)-1]
	if last.Outcome != "denied" || last.Args["error"] != codeApprovalForOtherUser {
		t.Fatalf("审计 = %+v", last)
	}
}

// uid 0 是 root 本人,不是"未指定":执行者是 root 时,requested_by_uid=0 的批准
// 必须放行到后续判定,而不是被当成坏记录。
func TestApprovalRootIsRequesterNotUnspecified(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	argv := []string{"systemctl", "--user", "start", "demo.service"}
	pendingID := pendingFromApply(t)
	swapExecutor(t, 0)
	writeApprovalRecord(t, f.approvals, pendingID, testArgvSHA256(argv), 0, time.Now())

	status, approval, err := loadApproval(pendingID, argv, time.Now())
	if status != approvalTrusted {
		t.Fatalf("root 自己签给 root 的批准应可信, 收到 status=%v err=%v", status, err)
	}
	if approval.RequestedByUID == nil || *approval.RequestedByUID != 0 {
		t.Fatalf("requested_by_uid = %v, 期望 0", approval.RequestedByUID)
	}
}

// 缺 requested_by_uid 的批准记录在解析阶段就被拒:缺失不等于 root,
// 否则所有"没写请求者"的记录都会对 root 的 agent 生效。
func TestApprovalMissingRequesterRejected(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	argv := []string{"systemctl", "--user", "start", "demo.service"}
	pendingID := pendingFromApply(t)

	rec := map[string]any{
		"id":          pendingID,
		"argv_sha256": testArgvSHA256(argv),
		"approved_by": "root",
		"approved_at": time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.approvals, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.approvals, pendingID+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	status, _, lerr := loadApproval(pendingID, argv, time.Now())
	if status != approvalUntrusted {
		t.Fatalf("缺请求者的批准必须按坏记录拒, 收到 status=%v err=%v", status, lerr)
	}
	if !strings.Contains(shortErrText(lerr), "requested_by_uid") {
		t.Fatalf("错误串应点明缺 requested_by_uid: %v", lerr)
	}

	// 走完整路径:一次都不许执行,也不许把"坏记录"读成"没有批准"。
	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.Error != codeApprovalUntrusted {
		t.Fatalf("期望 %s, 收到 %+v", codeApprovalUntrusted, rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 同一份批准第二次用 ⇒ approval_consumed,且两次之间 argv 完全一致:
// 这样拒绝理由是"用过了",不是"改了命令"(那是 approval_mismatch)。
func TestApprovalConsumedOnSecondUse(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	argv := []string{"systemctl", "--user", "start", "demo.service"}
	pendingID := pendingFromApply(t)
	writeApprovalRecord(t, f.approvals, pendingID, testArgvSHA256(argv), executorUID, time.Now())

	view, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej != nil {
		t.Fatalf("第一次用这份批准应执行, 收到拒绝 %+v", rej)
	}
	if view.Outcome != "applied" || view.PendingID != pendingID {
		t.Fatalf("view = %+v", view)
	}
	if got := appliedIn(t, readCalls(t, f.calls)); got != 1 {
		t.Fatalf("apply 应被调用一次, 实际 %d 次", got)
	}

	_, rej = txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.Error != codeApprovalConsumed {
		t.Fatalf("期望 %s, 收到 %+v", codeApprovalConsumed, rej)
	}
	// 重放不许执行第二次:一次性是"占住即烧掉",不是"再看一眼指纹"。
	if got := appliedIn(t, readCalls(t, f.calls)); got != 1 {
		t.Fatalf("重放又执行了一次: apply 共 %d 次", got)
	}
	lines := readAuditLines(t, f.auditLog)
	last := lines[len(lines)-1]
	if last.Outcome != "denied" || last.Args["error"] != codeApprovalConsumed {
		t.Fatalf("审计 = %+v", last)
	}
}

// O_EXCL 是这条机制的原子性来源:并发两次占同一份批准,必须恰好一次成功。
func TestClaimApprovalAtomic(t *testing.T) {
	newApplyFixture(t, obsUnknown)
	const id = "p-0123456789abcdef"

	errs := make([]error, 2)
	done := make(chan int, len(errs))
	for i := range errs {
		go func(i int) {
			errs[i] = claimApproval(id)
			done <- i
		}(i)
	}
	for range errs {
		<-done
	}

	claimed, consumed := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			claimed++
		case errors.Is(err, errApprovalConsumed):
			consumed++
		default:
			t.Fatalf("并发占批准出现意外错误: %v", err)
		}
	}
	if claimed != 1 || consumed != len(errs)-1 {
		t.Fatalf("成功=%d 已消费=%d, 期望 1/%d", claimed, consumed, len(errs)-1)
	}
}

// 消费目录属主不是自己 ⇒ fail-closed,且不许接管、不许 chmod:
// 别人的目录里放什么标记由别人说了算,那就在这里谈"用过了/没用过"。
func TestConsumedDirForeignOwnerFailsClosed(t *testing.T) {
	newApplyFixture(t, obsUnknown)
	// 换个执行者身份:目录由当前身份建,对新的执行者来说就是"别人的目录"。
	swapExecutor(t, executorUID+1)
	dir := consumedDirFor(executorUID)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	before := ownerOf(t, dir)
	beforeInfo, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}

	cerr := claimApproval("p-0123456789abcdef")
	if cerr == nil {
		t.Fatal("消费目录属主不符必须 fail-closed")
	}
	if errors.Is(cerr, errApprovalConsumed) {
		t.Fatal("属主不符不是\"已消费\":环境坏了与重放必须分得开")
	}
	if !strings.Contains(cerr.Error(), "sudo rm -rf "+dir) {
		t.Fatalf("错误串应给出处置步骤: %v", cerr)
	}
	if got := ownerOf(t, dir); got != before {
		t.Fatalf("消费目录属主被改动了: %d → %d", before, got)
	}
	afterInfo, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if afterInfo.Mode().Perm() != beforeInfo.Mode().Perm() {
		t.Fatalf("消费目录模式被改动了: %o → %o", beforeInfo.Mode().Perm(), afterInfo.Mode().Perm())
	}
	// 也不许把标记写到别处去"绕过"这个目录。
	entries, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("消费根目录下多出了东西(标记被写到别处?): %v", entries)
	}
}

// ownerOf 在 apply_pending_test.go 里定义;这里只用它读属主/模式,
// 顺便保证两处夹具的"属主"取法一致。

// 目录已存在的普通文件挡住消费目录 ⇒ claimApproval 失败(fail-closed),
// 不是"没消费过所以放行"。
func TestClaimApprovalRejectsNonDirectoryConsumedPath(t *testing.T) {
	newApplyFixture(t, obsUnknown)
	dir := consumedDirFor(executorUID)
	if err := os.WriteFile(dir, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := claimApproval("p-0123456789abcdef"); err == nil {
		t.Fatal("消费路径不是目录时必须 fail-closed")
	}
	// 修好之后能正常占住:失败不留下任何"已消费"的假象。
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := claimApproval("p-0123456789abcdef"); err != nil {
		t.Fatalf("消费目录恢复后应能占住: %v", err)
	}
}

// 消费标记目录的属主核对走的是同一套 ensureUserDir:新目录必须是当前执行者
// 的,且是 0700。
func TestClaimApprovalCreatesOwnedPrivateDir(t *testing.T) {
	newApplyFixture(t, obsUnknown)
	if err := claimApproval("p-0123456789abcdef"); err != nil {
		t.Fatalf("占住失败: %v", err)
	}
	dir := consumedDirFor(executorUID)
	if got := ownerOf(t, dir); got != executorUID {
		t.Fatalf("消费目录属主 = %d, 期望 %d", got, executorUID)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("消费目录模式 = %o, 期望 0700", perm)
	}
	marker, err := os.Lstat(filepath.Join(dir, "p-0123456789abcdef"))
	if err != nil {
		t.Fatalf("消费标记未落盘: %v", err)
	}
	if perm := marker.Mode().Perm(); perm != 0o600 {
		t.Fatalf("消费标记模式 = %o, 期望 0600", perm)
	}
	stat, ok := marker.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != executorUID {
		t.Fatalf("消费标记属主 = %v, 期望 %d", marker.Sys(), executorUID)
	}
}
