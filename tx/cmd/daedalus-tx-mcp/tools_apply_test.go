package main

// tools_apply_test.go —— tx_apply 的三档落地:自主执行、条子消费、待办+批准。
//
// 夹具一律用环境变量把条子/待办/批准/用量/审计落点指到临时目录,并把 txBinary
// 换成假 CLI:真 CLI 会真的动 systemctl,而这里要钉的是"谁被允许做什么"。
// 条子校验的每一条拒绝都必须能单独变红 —— 所以每个用例只破坏一个前提。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/audit"
	"github.com/Daedalusys/daedalus-sdk/autonomy"
	"github.com/Daedalusys/daedalus-sdk/grant"
)

// applyFakeCLI 是假 daedalus-tx:观测结果由 FAKE_OBSERVE_JSON 注入,begin 返回固定
// tx-id,propose/apply 回空文档。每次调用先把 argv 追加到 TX_CALL_LOG,用例据此断言
// "哪些子命令真的被调用了"。
const applyFakeCLI = `printf '%s\n' "$*" >> "$TX_CALL_LOG"
case "$1" in
  service-observe)
    printf '%s\n' "$FAKE_OBSERVE_JSON"
    ;;
  begin)
    printf '%s\n' '{"tx_id":"0123456789abcdef"}'
    ;;
  propose|apply)
    printf '%s\n' '{}'
    ;;
  *)
    printf '%s\n' '{"error":"unexpected subcommand"}'
    exit 2
    ;;
esac`

// 观测快照:三种判定入口。auto 要求 start + enabled + !running + known。
const (
	obsEnabledStopped = `{"unit":"demo.service","active_state":"inactive","unit_file_state":"enabled","enabled":true,"running":false,"known":true}`
	obsEnabledRunning = `{"unit":"demo.service","active_state":"active","unit_file_state":"enabled","enabled":true,"running":true,"known":true}`
	obsUnknown        = `{"unit":"demo.service","active_state":"unknown","unit_file_state":"unknown","enabled":false,"running":false,"known":false}`
)

// applyFixture 是每个用例独立的落点集合:所有路径都在临时目录里,互不干扰。
type applyFixture struct {
	calls     string
	txDir     string
	grantsDir string
	pending   string
	approvals string
	auditLog  string
}

// newApplyFixture 铺好隔离环境并装上假 CLI。observeJSON 决定档位判定看到的属性。
func newApplyFixture(t *testing.T, observeJSON string) applyFixture {
	t.Helper()
	isolateRuntime(t)
	root := t.TempDir()
	f := applyFixture{
		calls:     filepath.Join(root, "calls.log"),
		txDir:     filepath.Join(root, "tx"),
		grantsDir: filepath.Join(root, "grants"),
		pending:   filepath.Join(root, "pending"),
		approvals: filepath.Join(root, "approvals"),
		auditLog:  filepath.Join(root, "audit.jsonl"),
	}
	t.Setenv("DAEDALUS_TX_DIR", f.txDir)
	t.Setenv("DAEDALUS_GRANTS_DIR", f.grantsDir)
	t.Setenv("DAEDALUS_PENDING_DIR", f.pending)
	t.Setenv("DAEDALUS_APPROVALS_DIR", f.approvals)
	t.Setenv(audit.EnvLogPath, f.auditLog)
	t.Setenv("FAKE_OBSERVE_JSON", observeJSON)
	t.Setenv("TX_CALL_LOG", f.calls)
	installFakeTxScript(t, applyFakeCLI)
	if err := os.MkdirAll(f.grantsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 待办根目录在生产由 systemd-tmpfiles 以 1777 建好:夹具按同一形状铺好,
	// 插件自己只建 <根>/<uid> 那层。
	if err := os.MkdirAll(f.pending, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.pending, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	// 用量折叠是进程级状态:每个用例从空账本开始,否则前一个用例的消费会漏进来。
	grantUsage = newUsageLedger()
	// 批准目录要求 root 属主;测试进程不是 root,把"预期的属主"对齐到当前用户,
	// 让"批准可信 ⇒ 执行"这条路径可测。属主不符的拒绝由专门用例覆盖。
	oldUID := approvalDirOwnerUID
	approvalDirOwnerUID = uint32(os.Geteuid())
	t.Cleanup(func() { approvalDirOwnerUID = oldUID })
	return f
}

// signerConfig 给出出厂预设 + 一个能签本机用户的签发者。
// 非 root 测试用户必须显式出现在名单里 —— 这正是"伪造 issued_by 无效"的前提。
func signerConfig(t *testing.T) *autonomy.Config {
	t.Helper()
	cfg := autonomy.Default()
	signer, err := user.Current()
	if err != nil {
		t.Fatalf("取当前用户失败: %v", err)
	}
	cfg.Signers = []autonomy.Signer{{
		User:     signer.Username,
		MaxScope: []string{"systemd:user:start:*", "systemd:user:stop:*", "systemd:user:restart:*"},
		MaxTTL:   time.Hour,
		MaxUses:  5,
	}}
	return &cfg
}

// writeGrantFile 落一张条子:文件属主天然是当前测试用户,也就是消费侧认定的签发者。
func writeGrantFile(t *testing.T, dir string, g grant.Grant) string {
	t.Helper()
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("序列化条子: %v", err)
	}
	path := filepath.Join(dir, g.ID+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("写条子 %s: %v", path, err)
	}
	return path
}

// makeGrant 造一张形态合法的条子。到期时间早于签发时间时自动把签发时间再往前挪,
// 这样"过期条子"用例不会先倒在 Parse 的时序校验上。
func makeGrant(id, scope string, maxUses int, expiresIn time.Duration) grant.Grant {
	now := time.Now().UTC()
	expiresAt := now.Add(expiresIn)
	issuedAt := now.Add(-time.Minute)
	if !expiresAt.After(issuedAt) {
		issuedAt = expiresAt.Add(-time.Minute)
	}
	return grant.Grant{
		ID:        id,
		Scope:     []string{scope},
		IssuedBy:  "lofibass",
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		MaxUses:   maxUses,
	}
}

// writeApproval 落一条批准记录:与 daedalus-tx approve 的线上形状逐字一致。
func writeApproval(t *testing.T, dir, id, argvSHA, approvedBy string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := map[string]any{
		"id":          id,
		"argv_sha256": argvSHA,
		// 请求者权威 = 待办文件的 stat 属主;测试进程写待办,所以请求者就是自己。
		"requested_by_uid": executorUID,
		"approved_by":      approvedBy,
		"approved_at":      time.Now().UTC().Format(time.RFC3339),
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

// testArgvSHA256 独立复刻"被批准的是哪条 argv"的指纹算法(NUL 连接后 sha256)。
// 刻意不复用生产代码的助手:用例要能证明契约,而不是证明实现自己跟自己对得上。
func testArgvSHA256(argv []string) string {
	sum := sha256.Sum256([]byte(strings.Join(argv, "\x00")))
	return hex.EncodeToString(sum[:])
}

type auditLine struct {
	Identity string         `json:"identity"`
	Tool     string         `json:"tool"`
	Outcome  string         `json:"outcome"`
	Args     map[string]any `json:"args"`
}

func readAuditLines(t *testing.T, path string) []auditLine {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读审计 %s: %v", path, err)
	}
	var lines []auditLine
	for _, raw := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var line auditLine
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("审计行不是 JSON: %v (%s)", err, raw)
		}
		lines = append(lines, line)
	}
	return lines
}

// readCalls 读假 CLI 的调用流水(每行一条 argv)。
func readCalls(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("读调用流水 %s: %v", path, err)
	}
	var out []string
	for _, raw := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if raw != "" {
			out = append(out, raw)
		}
	}
	return out
}

// subcommands 只留每条 argv 的子命令名,便于断言执行路径。
func subcommands(calls []string) []string {
	out := make([]string, 0, len(calls))
	for _, line := range calls {
		out = append(out, strings.Fields(line)[0])
	}
	return out
}

func hasCall(calls []string, prefix string) bool {
	for _, line := range calls {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func requireNoChanges(t *testing.T, calls []string) {
	t.Helper()
	for _, line := range calls {
		if strings.HasPrefix(line, "begin") || strings.HasPrefix(line, "propose") || strings.HasPrefix(line, "apply") {
			t.Fatalf("期望不执行任何变更子命令, 实际调用: %q", line)
		}
	}
}

func appliedIn(t *testing.T, calls []string) int {
	t.Helper()
	n := 0
	for _, line := range calls {
		if strings.HasPrefix(line, "apply ") {
			n++
		}
	}
	return n
}

// auto 档必须真的走 begin/propose/apply 三步,propose 的步骤 args 是两键锁定 schema。
func TestTxApplyAutoTierApplies(t *testing.T) {
	f := newApplyFixture(t, obsEnabledStopped)

	view, rej := txApply(defaultConfig(), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "started", Actor: "ai-client",
	})
	if rej != nil {
		t.Fatalf("auto 档应执行, 收到拒绝 %+v", rej)
	}
	if view.Tier != string(autonomy.TierAuto) || view.Outcome != "applied" {
		t.Fatalf("tier/outcome = %s/%s, 期望 auto/applied", view.Tier, view.Outcome)
	}
	if view.TxID != "0123456789abcdef" {
		t.Fatalf("tx_id = %q", view.TxID)
	}
	if view.GrantID != "" {
		t.Fatalf("auto 档不该消费条子, grant_id = %q", view.GrantID)
	}

	calls := readCalls(t, f.calls)
	if got, want := subcommands(calls), []string{"service-observe", "begin", "propose", "apply"}; !equalStrings(got, want) {
		t.Fatalf("调用序列 = %v, 期望 %v", got, want)
	}
	// propose <tx-id> service.set <args-json>:args 只能是 name + desired_state 两键。
	fields := strings.Fields(calls[2])
	if len(fields) != 4 || fields[1] != "0123456789abcdef" || fields[2] != "service.set" {
		t.Fatalf("propose 调用形态不对: %q", calls[2])
	}
	if fields[3] != `{"name":"demo.service","desired_state":"started"}` {
		t.Fatalf("propose args = %s, 期望两键锁定 schema", fields[3])
	}

	lines := readAuditLines(t, f.auditLog)
	if len(lines) != 1 {
		t.Fatalf("期望 1 条审计, 收到 %d", len(lines))
	}
	line := lines[0]
	if line.Identity != serverName || line.Tool != "tx_apply" || line.Outcome != "success" {
		t.Fatalf("审计身份/工具/结果 = %s/%s/%s", line.Identity, line.Tool, line.Outcome)
	}
	if line.Args["tier"] != "auto" || line.Args["tx_id"] != "0123456789abcdef" {
		t.Fatalf("审计 args = %v", line.Args)
	}
	if line.Args["actor"] != "ai-client" {
		t.Fatalf("actor 线索应原样入审计: %v", line.Args["actor"])
	}
	if _, ok := line.Args["decision_path"]; !ok {
		t.Fatalf("审计缺 decision_path: %v", line.Args)
	}
}

// 第二档没条子:拒绝且必须给出 required_scope,并且绝不调用 apply。
func TestTxApplyConfirmTierWithoutGrantIsRejected(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)

	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "restarted"})
	if rej == nil {
		t.Fatal("confirm 档无条子应被拒")
	}
	if rej.Error != "grant_required" {
		t.Fatalf("error = %q, 期望 grant_required", rej.Error)
	}
	if rej.Tier != string(autonomy.TierConfirm) {
		t.Fatalf("tier = %q", rej.Tier)
	}
	if got, want := rej.RequiredScope, []string{"systemd:user:restart:demo.service"}; !equalStrings(got, want) {
		t.Fatalf("required_scope = %v, 期望 %v", got, want)
	}
	if rej.Reason == "" {
		t.Fatal("拒绝必须带可读理由")
	}
	requireNoChanges(t, readCalls(t, f.calls))
	lines := readAuditLines(t, f.auditLog)
	if len(lines) != 1 || lines[0].Outcome != "denied" {
		t.Fatalf("拒绝必须落 denied 审计: %+v", lines)
	}
}

// 第二档有匹配条子:执行,审计带 grant_id,用量记账落盘,且条子明文不进审计。
func TestTxApplyConfirmTierWithGrantApplies(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261120-aaaaaaaa", "systemd:user:restart:demo.service", 2, 30*time.Minute)
	g.Note = "半夜挂了就重启-不该进审计"
	writeGrantFile(t, f.grantsDir, g)

	view, rej := txApply(signerConfig(t), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: g.ID,
	})
	if rej != nil {
		t.Fatalf("有匹配条子应执行, 收到拒绝 %+v", rej)
	}
	if view.Outcome != "applied" || view.GrantID != g.ID || view.TxID == "" {
		t.Fatalf("view = %+v", view)
	}
	if appliedIn(t, readCalls(t, f.calls)) != 1 {
		t.Fatal("apply 应恰好被调用一次")
	}

	lines := readAuditLines(t, f.auditLog)
	if len(lines) != 1 {
		t.Fatalf("期望 1 条审计, 收到 %d", len(lines))
	}
	if lines[0].Args["grant_id"] != g.ID || lines[0].Args["tier"] != "confirm" {
		t.Fatalf("审计 args = %v", lines[0].Args)
	}
	raw, err := os.ReadFile(f.auditLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), g.Note) {
		t.Fatal("条子明文(note)不得进审计链")
	}

	usage, err := os.ReadFile(filepath.Join(f.txDir, grant.UsageFileNameFor(executorUID)))
	if err != nil {
		t.Fatalf("用量记账未落盘: %v", err)
	}
	if !strings.Contains(string(usage), g.ID) {
		t.Fatalf("用量记账缺条子 id: %s", usage)
	}
}

// 伪造条子:JSON 里自称 root,但文件属主是普通用户且不在签发者名单 ⇒ 拒绝。
// 这条用例在 root 下没有意义(root 恒可签),故显式跳过。
func TestTxApplyRejectsForgedGrant(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 恒可签, 伪造签发者身份无从构造")
	}
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261120-bbbbbbbb", "systemd:user:restart:demo.service", 1, 30*time.Minute)
	g.IssuedBy = "root" // 篡改自报身份,消费侧不认
	writeGrantFile(t, f.grantsDir, g)

	_, rej := txApply(defaultConfig(), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: g.ID,
	})
	if rej == nil {
		t.Fatal("伪造签发者的条子必须被拒")
	}
	if rej.Error != "grant_unauthorized" {
		t.Fatalf("error = %q, 期望 grant_unauthorized", rej.Error)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 伪造条子:签发者手写一份超出自己授权的条子(范围或时长越界)⇒ 消费侧拒。
// 这条用例证明"签发时的校验"不是必要条件:消费侧会重判一遍。
func TestTxApplyRejectsGrantBeyondSignerAuthority(t *testing.T) {
	t.Run("beyond max_scope", func(t *testing.T) {
		f := newApplyFixture(t, obsEnabledRunning)
		cfg := autonomy.Default()
		signer, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		cfg.Signers = []autonomy.Signer{{
			User:     signer.Username,
			MaxScope: []string{"systemd:user:start:*"},
			MaxTTL:   time.Hour,
			MaxUses:  5,
		}}
		g := makeGrant("g-20261120-66666666", "systemd:user:restart:demo.service", 1, 30*time.Minute)
		writeGrantFile(t, f.grantsDir, g)

		_, rej := txApply(&cfg, applyIn{
			Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: g.ID,
		})
		if rej == nil || rej.Error != "grant_unauthorized" {
			t.Fatalf("期望 grant_unauthorized, 收到 %+v", rej)
		}
		requireNoChanges(t, readCalls(t, f.calls))
	})

	t.Run("beyond max_ttl", func(t *testing.T) {
		f := newApplyFixture(t, obsEnabledRunning)
		cfg := autonomy.Default()
		signer, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		cfg.Signers = []autonomy.Signer{{
			User:     signer.Username,
			MaxScope: []string{"systemd:user:restart:*"},
			MaxTTL:   10 * time.Minute,
			MaxUses:  5,
		}}
		g := makeGrant("g-20261120-77777777", "systemd:user:restart:demo.service", 1, 40*time.Minute)
		writeGrantFile(t, f.grantsDir, g)

		_, rej := txApply(&cfg, applyIn{
			Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: g.ID,
		})
		if rej == nil || rej.Error != "grant_unauthorized" {
			t.Fatalf("期望 grant_unauthorized, 收到 %+v", rej)
		}
		requireNoChanges(t, readCalls(t, f.calls))
	})
}

// 条子文件名与文件内 id 不一致:两份事实源对不上,不能挑一份信。
func TestTxApplyRejectsGrantWithMismatchedFileID(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261120-88888888", "systemd:user:restart:demo.service", 1, 30*time.Minute)
	// 故意用另一个文件名落盘,内容里的 id 仍是 g.ID。
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	other := "g-20261120-99999999"
	if err := os.WriteFile(filepath.Join(f.grantsDir, other+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	_, rej := txApply(signerConfig(t), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: other,
	})
	if rej == nil || rej.Error != "grant_invalid" {
		t.Fatalf("期望 grant_invalid, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 过期条子:独立可区分的理由,不与"用尽/作用域不符/被撤销"混为一谈。
func TestTxApplyRejectsExpiredGrant(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261120-cccccccc", "systemd:user:restart:demo.service", 1, -30*time.Minute)
	writeGrantFile(t, f.grantsDir, g)

	_, rej := txApply(signerConfig(t), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: g.ID,
	})
	if rej == nil || rej.Error != "grant_expired" {
		t.Fatalf("期望 grant_expired, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 用尽条子:用量记账里已经有 max_uses 次消费 ⇒ 拒绝,且不写新的记账。
func TestTxApplyRejectsExhaustedGrant(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261120-dddddddd", "systemd:user:restart:demo.service", 1, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, g)
	if err := os.MkdirAll(f.txDir, 0o755); err != nil {
		t.Fatal(err)
	}
	seed := fmt.Sprintf("{\"grant_id\":%q,\"used_at\":%q}\n",
		g.ID, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano))
	if err := os.WriteFile(filepath.Join(f.txDir, grant.UsageFileNameFor(executorUID)), []byte(seed), 0o640); err != nil {
		t.Fatal(err)
	}

	_, rej := txApply(signerConfig(t), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: g.ID,
	})
	if rej == nil || rej.Error != "grant_exhausted" {
		t.Fatalf("期望 grant_exhausted, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 作用域不符:条子签的是 restart,本次动作是 stop ⇒ 拒绝,理由里必须出现"作用域"。
func TestTxApplyRejectsScopeMismatch(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261120-eeeeeeee", "systemd:user:restart:*", 2, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, g)

	_, rej := txApply(signerConfig(t), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "stopped", GrantID: g.ID,
	})
	if rej == nil || rej.Error != "grant_scope_mismatch" {
		t.Fatalf("期望 grant_scope_mismatch, 收到 %+v", rej)
	}
	if !strings.Contains(rej.Reason, "作用域") {
		t.Fatalf("理由应提到作用域: %q", rej.Reason)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 被撤销条子:文件已被删除(撤销=删文件),与"根本没提供条子"必须可区分。
func TestTxApplyRejectsRevokedGrant(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)

	_, rej := txApply(signerConfig(t), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: "g-20261120-ffffffff",
	})
	if rej == nil || rej.Error != "grant_revoked" {
		t.Fatalf("期望 grant_revoked, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 记账失败必须 fail-closed:先记账再执行,记不上就不许执行。
func TestTxApplyFailsClosedWhenUsageRecordingFails(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261120-11111111", "systemd:user:restart:demo.service", 1, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, g)
	// 空值的覆盖变量是误配置(dirs 明确拒绝),用量日志路径解析因此失败。
	t.Setenv("DAEDALUS_TX_DIR", "")

	_, rej := txApply(signerConfig(t), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: g.ID,
	})
	if rej == nil || rej.Error != "grant_usage_failed" {
		t.Fatalf("期望 grant_usage_failed, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 单次性在进程内的并发下必须成立:SDK 只有"读计数/追加计数"两个原语,
// "读→判→记"三步由消费侧的同一把互斥锁兜住,否则 8 个并发能花掉一张一次条子。
func TestTxApplyGrantSingleUseUnderConcurrency(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)
	g := makeGrant("g-20261120-22222222", "systemd:user:restart:demo.service", 1, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, g)
	cfg := signerConfig(t)

	const workers = 8
	views := make([]applyView, workers)
	rejs := make([]*applyRejection, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			views[i], rejs[i] = txApply(cfg, applyIn{
				Kind: "service", Name: "demo.service", DesiredState: "restarted", GrantID: g.ID,
			})
		}(i)
	}
	wg.Wait()

	applied, exhausted := 0, 0
	for i := 0; i < workers; i++ {
		switch {
		case rejs[i] == nil && views[i].Outcome == "applied":
			applied++
		case rejs[i] != nil && rejs[i].Error == "grant_exhausted":
			exhausted++
		default:
			t.Fatalf("并发结果不在预期集合: view=%+v rej=%+v", views[i], rejs[i])
		}
	}
	if applied != 1 || exhausted != workers-1 {
		t.Fatalf("applied=%d exhausted=%d, 期望 1/%d", applied, exhausted, workers-1)
	}
	if got := appliedIn(t, readCalls(t, f.calls)); got != 1 {
		t.Fatalf("apply 被调用 %d 次, 期望 1", got)
	}
}

// 第三档只出待办:写 pending(含 argv),不写批准记录,不执行。
func TestTxApplyHumanTierWritesPending(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)

	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil {
		t.Fatal("human 档应被拒(不执行)")
	}
	if rej.Error != "human_approval_required" || rej.Tier != string(autonomy.TierHuman) {
		t.Fatalf("rejection = %+v", rej)
	}
	if rej.PendingID == "" {
		t.Fatal("human 档必须给出 pending_id")
	}
	if got, want := rej.Argv, []string{"systemctl", "--user", "start", "demo.service"}; !equalStrings(got, want) {
		t.Fatalf("argv = %v, 期望 %v", got, want)
	}
	// 提案必须带上 argv 指纹:人抄给 approve --expect-sha256 的就是它。
	if rej.ArgvSHA256 != testArgvSHA256(rej.Argv) {
		t.Fatalf("argv_sha256 = %q, 期望 %q", rej.ArgvSHA256, testArgvSHA256(rej.Argv))
	}

	data, err := os.ReadFile(filepath.Join(userPendingDir(f.pending), rej.PendingID+".json"))
	if err != nil {
		t.Fatalf("待办未落盘: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("待办不是 JSON: %v", err)
	}
	for _, key := range []string{"id", "kind", "name", "desired_state", "argv", "scope", "reason", "created_at", "expires_at"} {
		if _, ok := doc[key]; !ok {
			t.Fatalf("待办缺字段 %q: %s", key, data)
		}
	}
	if doc["id"] != rej.PendingID || doc["scope"] != "systemd:user:start:demo.service" {
		t.Fatalf("待办内容 = %s", data)
	}

	entries, err := os.ReadDir(f.approvals)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("AI 不能给自己写批准记录: %v", entries)
	}
	requireNoChanges(t, readCalls(t, f.calls))
	// 出待办不是拒绝:审计记 proposed,并且带 tier=human。
	lines := readAuditLines(t, f.auditLog)
	if len(lines) != 1 || lines[0].Outcome != "proposed" || lines[0].Args["tier"] != "human" {
		t.Fatalf("审计 = %+v", lines)
	}
	if lines[0].Args["pending_id"] != rej.PendingID {
		t.Fatalf("审计 pending_id = %v", lines[0].Args["pending_id"])
	}
}

// 第三档即使有有效条子也不执行:条子不构成人亲手档位的许可。
func TestTxApplyHumanTierIgnoresValidGrant(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	g := makeGrant("g-20261120-33333333", "systemd:user:start:demo.service", 2, 30*time.Minute)
	writeGrantFile(t, f.grantsDir, g)

	_, rej := txApply(signerConfig(t), applyIn{
		Kind: "service", Name: "demo.service", DesiredState: "started", GrantID: g.ID,
	})
	if rej == nil || rej.Error != "human_approval_required" {
		t.Fatalf("期望 human_approval_required, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 有批准记录且 argv 逐字一致 ⇒ 以调用者身份执行(不是 root 代跑)。
func TestTxApplyHumanTierWithApprovalExecutes(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	argv := []string{"systemctl", "--user", "start", "demo.service"}

	// 第一次调用拿到确定性的待办 id(AI 出待办)。
	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.PendingID == "" {
		t.Fatalf("第一次调用应出待办: %+v", rej)
	}
	pendingID := rej.PendingID
	writeApproval(t, f.approvals, pendingID, testArgvSHA256(argv), "root")

	view, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej != nil {
		t.Fatalf("批准后应执行, 收到拒绝 %+v", rej)
	}
	if view.Outcome != "applied" || view.Tier != string(autonomy.TierHuman) || view.ApprovedBy != "root" {
		t.Fatalf("view = %+v", view)
	}
	if view.PendingID != pendingID {
		t.Fatalf("pending_id = %q, 期望 %q", view.PendingID, pendingID)
	}
	calls := readCalls(t, f.calls)
	if appliedIn(t, calls) != 1 {
		t.Fatalf("apply 应被调用一次: %v", calls)
	}
	lines := readAuditLines(t, f.auditLog)
	last := lines[len(lines)-1]
	if last.Outcome != "success" || last.Args["approved_by"] != "root" || last.Args["tier"] != "human" {
		t.Fatalf("审计 = %+v", last)
	}
}

// 批准绑定的是具体 argv:指纹不一致 ⇒ 拒绝,参数变了就是新动作。
func TestTxApplyHumanTierWithMismatchedApprovalIsRejected(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.PendingID == "" {
		t.Fatalf("第一次调用应出待办: %+v", rej)
	}
	// 人批的是另一条 argv(restart),与本次要跑的 start 不是同一动作。
	wrong := testArgvSHA256([]string{"systemctl", "--user", "restart", "demo.service"})
	writeApproval(t, f.approvals, rej.PendingID, wrong, "root")

	_, rej = txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.Error != "approval_mismatch" {
		t.Fatalf("期望 approval_mismatch, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 幂等:已经在位就直接 noop,不建事务、不调 apply,但审计要留痕。
func TestTxApplyIsIdempotentWhenAlreadyInDesiredState(t *testing.T) {
	f := newApplyFixture(t, obsEnabledRunning)

	view, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej != nil {
		t.Fatalf("幂等路径不该被拒: %+v", rej)
	}
	if view.Outcome != "noop" || view.TxID != "" {
		t.Fatalf("view = %+v", view)
	}
	requireNoChanges(t, readCalls(t, f.calls))
	lines := readAuditLines(t, f.auditLog)
	if len(lines) != 1 || lines[0].Outcome != "noop" {
		t.Fatalf("幂等路径必须落 noop 审计: %+v", lines)
	}
}

// 单元名必须以 .service 结尾:不做隐式补后缀,观测与 propose 吃同一个字面量。
func TestTxApplyRejectsNonServiceUnitName(t *testing.T) {
	f := newApplyFixture(t, obsEnabledStopped)
	for _, name := range []string{"demo.timer", "demo"} {
		_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: name, DesiredState: "started"})
		if rej == nil || rej.Error != "invalid_name" {
			t.Fatalf("name=%q 期望 invalid_name, 收到 %+v", name, rej)
		}
	}
	// 名称门在观测之前:连 service-observe 都不该被调用。
	if calls := readCalls(t, f.calls); len(calls) != 0 {
		t.Fatalf("非法单元名不该触发任何 CLI 调用: %v", calls)
	}
}

// 经真实 MCP 会话的端到端:tx_apply 不再是占位,成功时回结构化视图。
func TestTxApplyThroughMCPSessionApplies(t *testing.T) {
	f := newApplyFixture(t, obsEnabledStopped)
	session, closeSession := connectTestSession(t, defaultConfig())
	defer closeSession()

	res := callToolText(t, session, "tx_apply", map[string]any{
		"kind": "service", "name": "demo.service", "desired_state": "started",
	})
	if res.IsError {
		t.Fatalf("auto 档经 MCP 应成功: %s", res.text)
	}
	var view applyView
	if err := json.Unmarshal([]byte(res.text), &view); err != nil {
		t.Fatalf("返回不是 JSON: %v\n%s", err, res.text)
	}
	if view.Outcome != "applied" || view.Tier != "auto" || view.TxID == "" {
		t.Fatalf("view = %+v", view)
	}
	if appliedIn(t, readCalls(t, f.calls)) != 1 {
		t.Fatal("apply 应被调用一次")
	}
}

// 拒绝面经 MCP 也必须带机器可读码与 required_scope。
func TestTxApplyThroughMCPSessionReturnsStructuredRejection(t *testing.T) {
	newApplyFixture(t, obsEnabledRunning)
	session, closeSession := connectTestSession(t, defaultConfig())
	defer closeSession()

	res := callToolText(t, session, "tx_apply", map[string]any{
		"kind": "service", "name": "demo.service", "desired_state": "restarted",
	})
	if !res.IsError {
		t.Fatal("confirm 档无条子必须标记 isError")
	}
	var rej applyRejection
	if err := json.Unmarshal([]byte(res.text), &rej); err != nil {
		t.Fatalf("拒绝不是结构化 JSON: %v\n%s", err, res.text)
	}
	if rej.Error != "grant_required" || rej.Tier != "confirm" || len(rej.RequiredScope) != 1 {
		t.Fatalf("rejection = %+v", rej)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// toolText 是单文本块工具结果的紧凑视图。
type toolText struct {
	text    string
	IsError bool
}

func callToolText(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) toolText {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("%s 期望单文本块, 收到 %d 块", name, len(res.Content))
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s 内容类型 = %T", name, res.Content[0])
	}
	return toolText{text: text.Text, IsError: res.IsError}
}

// requireNoPending 断言没有新待办:批准不可信时不能退化成"重新申请"。
func requireNoPending(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("不该写出待办: %v", entries)
	}
}

// 批准目录被换成符号链接:批准不可信 ⇒ 拒绝,且不重新出待办。
func TestTxApplyRejectsSymlinkedApprovalsDir(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	realDir := filepath.Join(t.TempDir(), "real-approvals")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, f.approvals); err != nil {
		t.Fatal(err)
	}

	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.Error != "approval_untrusted" {
		t.Fatalf("期望 approval_untrusted, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
	requireNoPending(t, f.pending)
}

// 批准目录组/其他可写:这道门就不存在了,按批准不可信拒绝。
func TestTxApplyRejectsWritableApprovalsDir(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	if err := os.MkdirAll(f.approvals, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.approvals, 0o777); err != nil {
		t.Fatal(err)
	}

	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.Error != "approval_untrusted" {
		t.Fatalf("期望 approval_untrusted, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 批准目录属主不是 root:目录里的文件不再只可能由 root 写,批准无效。
func TestTxApplyRejectsUnexpectedApprovalsDirOwner(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	if err := os.MkdirAll(f.approvals, 0o755); err != nil {
		t.Fatal(err)
	}
	approvalDirOwnerUID = uint32(os.Geteuid()) + 1

	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.Error != "approval_untrusted" {
		t.Fatalf("期望 approval_untrusted, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}

// 批准记录被换成符号链接:内容来自批准目录之外,按批准不可信拒绝。
func TestTxApplyRejectsSymlinkedApprovalRecord(t *testing.T) {
	f := newApplyFixture(t, obsUnknown)
	_, rej := txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.PendingID == "" {
		t.Fatalf("第一次调用应出待办: %+v", rej)
	}
	argv := []string{"systemctl", "--user", "start", "demo.service"}
	realPath := filepath.Join(t.TempDir(), "approval.json")
	rec := fmt.Sprintf(`{"id":%q,"argv_sha256":%q,"requested_by_uid":%d,"approved_by":"root","approved_at":%q}`,
		rej.PendingID, testArgvSHA256(argv), executorUID, time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(realPath, []byte(rec), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.approvals, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, filepath.Join(f.approvals, rej.PendingID+".json")); err != nil {
		t.Fatal(err)
	}

	_, rej = txApply(defaultConfig(), applyIn{Kind: "service", Name: "demo.service", DesiredState: "started"})
	if rej == nil || rej.Error != "approval_untrusted" {
		t.Fatalf("期望 approval_untrusted, 收到 %+v", rej)
	}
	requireNoChanges(t, readCalls(t, f.calls))
}
