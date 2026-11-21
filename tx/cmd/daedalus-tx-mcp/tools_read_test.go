package main

// tools_read_test.go —— tx_status / tx_list / tx_pending / tx_rollback 的读面与回滚门。
//
// 读面要钉的是"看到的与 journal 里写的一致";回滚要钉的是"它不是免票通道":
// 第三档目标必须被拒,而且拒绝发生在调用 tx CLI 的 rollback 之前。夹具一律用
// 环境变量把日志/待办/审计落点指到临时目录,并把 txBinary 换成假 CLI。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/audit"
	"github.com/Daedalusys/daedalus-sdk/autonomy"
)

// readFakeCLI 只回放读面与回滚:status 由 FAKE_STATUS_JSON 注入,service-observe
// 由 FAKE_OBSERVE_JSON 注入,rollback 回一份成功日志。调用流水用来证明
// "拒绝时 rollback 一次都没发生"。
const readFakeCLI = `printf '%s\n' "$*" >> "$TX_CALL_LOG"
case "$1" in
  service-observe)
    printf '%s\n' "$FAKE_OBSERVE_JSON"
    ;;
  status)
    printf '%s\n' "$FAKE_STATUS_JSON"
    ;;
  rollback)
    printf '%s\n' '{"id":"0123456789abcdef","status":"rolled_back","steps":[]}'
    ;;
  *)
    printf '%s\n' '{"error":"unexpected subcommand"}'
    exit 2
    ;;
esac`

// readFixture 是读面用例的隔离落点。
type readFixture struct {
	calls    string
	txDir    string
	pending  string
	auditLog string
}

// newReadFixture 铺好隔离环境并装上假 CLI。statusJSON 决定 status 子命令的应答;
// 空串表示该用例不调用 status(如 tx_list 直接读日志目录)。
func newReadFixture(t *testing.T, observeJSON, statusJSON string) readFixture {
	t.Helper()
	isolateRuntime(t)
	root := t.TempDir()
	f := readFixture{
		calls:    filepath.Join(root, "calls.log"),
		txDir:    filepath.Join(root, "tx"),
		pending:  filepath.Join(root, "pending"),
		auditLog: filepath.Join(root, "audit.jsonl"),
	}
	t.Setenv("DAEDALUS_TX_DIR", f.txDir)
	t.Setenv("DAEDALUS_PENDING_DIR", f.pending)
	t.Setenv(audit.EnvLogPath, f.auditLog)
	t.Setenv("FAKE_OBSERVE_JSON", observeJSON)
	t.Setenv("FAKE_STATUS_JSON", statusJSON)
	t.Setenv("TX_CALL_LOG", f.calls)
	installFakeTxScript(t, readFakeCLI)
	if err := os.MkdirAll(f.txDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

// writeJournal 落一份最小 journal:名字即 id,内容含 id/created_at/status/steps。
func writeJournal(t *testing.T, dir, id, status, createdAt string, steps []any) string {
	t.Helper()
	if steps == nil {
		steps = []any{}
	}
	doc := map[string]any{
		"id":         id,
		"created_at": createdAt,
		"status":     status,
		"steps":      steps,
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writePendingFixture 落一份待办,形状与 daedalus-tx approve 的线上契约一致。
func writePendingFixture(t *testing.T, dir, id string, argv []string) string {
	t.Helper()
	doc := pendingDoc{
		ID:           id,
		Kind:         kindService,
		Name:         "demo.service",
		DesiredState: "restarted",
		Argv:         argv,
		Scope:        "systemd:user:restart:demo.service",
		Reason:       "tier=human (deny)",
		CreatedAt:    "2026-11-20T10:00:00Z",
		ExpiresAt:    "2026-11-20T11:00:00Z",
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// tx_status 把 CLI 的 id/status/steps 原样映射成 tx_id/state/steps,不多不少。
func TestTxStatusPassesThroughCoreFields(t *testing.T) {
	txID := "0123456789abcdef"
	statusJSON := `{"id":"` + txID + `","created_at":"2026-11-20T10:00:00Z","status":"applied",` +
		`"steps":[{"index":0,"adapter":"service.set","args":{"name":"demo.service","desired_state":"started"}}],` +
		`"rollback_plan":{"steps":[]}}`
	f := newReadFixture(t, obsEnabledRunning, statusJSON)

	view, serr := txStatus(statusIn{TxID: txID})
	if serr != nil {
		t.Fatalf("期望成功, 收到 %+v", serr)
	}
	if view.TxID != txID || view.State != "applied" {
		t.Fatalf("view = %+v", view)
	}
	if len(view.Steps) != 1 {
		t.Fatalf("steps = %d, 期望 1", len(view.Steps))
	}
	var step map[string]any
	if err := json.Unmarshal(view.Steps[0], &step); err != nil {
		t.Fatalf("step 不是 JSON: %v", err)
	}
	if step["adapter"] != adapterServiceSet {
		t.Fatalf("step adapter = %v", step["adapter"])
	}

	calls := readCalls(t, f.calls)
	if !hasCall(calls, "status "+txID) {
		t.Fatalf("未调用 status: %q", calls)
	}
	for _, line := range calls {
		if strings.HasPrefix(line, "begin") || strings.HasPrefix(line, "apply") || strings.HasPrefix(line, "rollback") {
			t.Fatalf("只读工具不应触发变更: %q", line)
		}
	}
}

// 非法 tx-id 在触碰 CLI/日志路径之前就被拒。
func TestTxStatusRejectsMalformedTxID(t *testing.T) {
	f := newReadFixture(t, obsEnabledRunning, "")

	_, serr := txStatus(statusIn{TxID: "../etc/passwd"})
	if serr == nil || serr.Error != codeInvalidTxID {
		t.Fatalf("serr = %+v, 期望 %s", serr, codeInvalidTxID)
	}
	if calls := readCalls(t, f.calls); len(calls) != 0 {
		t.Fatalf("非法 id 不应调用 CLI: %q", calls)
	}
}

// tx_list 直接读日志目录:时间倒序、limit 生效、杂散文件不参与。
func TestTxListOrdersDescendingAndRespectsLimit(t *testing.T) {
	f := newReadFixture(t, obsEnabledRunning, "")
	writeJournal(t, f.txDir, "aaaaaaaaaaaaaaaa", "applied", "2026-11-20T10:00:00Z", nil)
	writeJournal(t, f.txDir, "bbbbbbbbbbbbbbbb", "failed", "2026-11-20T12:00:00Z", nil)
	writeJournal(t, f.txDir, "cccccccccccccccc", "proposed", "2026-11-20T11:00:00Z", nil)
	// 杂散文件不是 journal:不该让 list 变红,也不该出现在结果里。
	if err := os.WriteFile(filepath.Join(f.txDir, "notatx.json"), []byte(`{"id":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.txDir, "notes.txt"), []byte("ignore"), 0o644); err != nil {
		t.Fatal(err)
	}

	all, serr := txList(listIn{})
	if serr != nil {
		t.Fatalf("期望成功, 收到 %+v", serr)
	}
	var ids []string
	for _, item := range all.Items {
		ids = append(ids, item.TxID)
	}
	want := []string{"bbbbbbbbbbbbbbbb", "cccccccccccccccc", "aaaaaaaaaaaaaaaa"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("顺序 = %v, 期望 %v", ids, want)
	}
	if all.Items[0].State != "failed" || all.Items[0].CreatedAt.IsZero() {
		t.Fatalf("首项 = %+v", all.Items[0])
	}

	limited, serr := txList(listIn{Limit: 2})
	if serr != nil {
		t.Fatalf("期望成功, 收到 %+v", serr)
	}
	if len(limited.Items) != 2 || limited.Items[0].TxID != "bbbbbbbbbbbbbbbb" || limited.Items[1].TxID != "cccccccccccccccc" {
		t.Fatalf("limit=2 结果 = %+v", limited.Items)
	}

	if calls := readCalls(t, f.calls); len(calls) != 0 {
		t.Fatalf("tx_list 不应调用 CLI: %q", calls)
	}
}

// 形状合法的 journal 读不出来 = journal 损坏,如实报错而不是静默少一条。
func TestTxListFailsOnCorruptJournal(t *testing.T) {
	f := newReadFixture(t, obsEnabledRunning, "")
	if err := os.WriteFile(filepath.Join(f.txDir, "aaaaaaaaaaaaaaaa.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, serr := txList(listIn{})
	if serr == nil || serr.Error != codeTxFailed {
		t.Fatalf("serr = %+v, 期望 %s", serr, codeTxFailed)
	}
}

// tx_pending 只列待办 *.json;argv 原样透出,argv_sha256 是同一算法算出的指纹;
// 整个调用不写任何东西。
func TestTxPendingListsOnlyPendingFiles(t *testing.T) {
	f := newReadFixture(t, obsEnabledRunning, "")
	argv := []string{"systemctl", "--user", "restart", "demo.service"}
	writePendingFixture(t, f.pending, "p-0123456789abcdef", argv)
	if err := os.WriteFile(filepath.Join(f.pending, "notes.txt"), []byte("ignore"), 0o644); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadDir(f.pending)
	if err != nil {
		t.Fatal(err)
	}

	view, serr := txPending()
	if serr != nil {
		t.Fatalf("期望成功, 收到 %+v", serr)
	}
	if len(view.Items) != 1 {
		t.Fatalf("items = %d, 期望 1: %+v", len(view.Items), view.Items)
	}
	item := view.Items[0]
	if item.ID != "p-0123456789abcdef" || item.Scope != "systemd:user:restart:demo.service" {
		t.Fatalf("item = %+v", item)
	}
	if len(item.Argv) == 0 {
		t.Fatal("argv 为空,人无法据此批准")
	}
	if !reflect.DeepEqual(item.Argv, argv) {
		t.Fatalf("argv = %v, 期望 %v", item.Argv, argv)
	}
	if item.ArgvSHA256 != testArgvSHA256(argv) {
		t.Fatalf("argv_sha256 = %q, 期望 %q", item.ArgvSHA256, testArgvSHA256(argv))
	}
	if item.CreatedAt == "" || item.ExpiresAt == "" || item.Reason == "" {
		t.Fatalf("待办字段不全: %+v", item)
	}

	after, err := os.ReadDir(f.pending)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("tx_pending 写了文件: before=%d after=%d", len(before), len(after))
	}
}

// 待办目录不存在 ⇒ 空列表,不是错误(全新机器还没出过待办)。
func TestTxPendingMissingDirIsEmpty(t *testing.T) {
	newReadFixture(t, obsEnabledRunning, "")

	view, serr := txPending()
	if serr != nil {
		t.Fatalf("期望空列表, 收到 %+v", serr)
	}
	if len(view.Items) != 0 {
		t.Fatalf("items = %+v", view.Items)
	}
}

// 回滚不是免票通道:第三档目标必须拒绝,且 rollback 子命令一次都不许被调用。
func TestTxRollbackIsSubjectToTier(t *testing.T) {
	txID := "0123456789abcdef"
	statusJSON := `{"id":"` + txID + `","created_at":"2026-11-20T10:00:00Z","status":"applied",` +
		`"steps":[{"index":0,"adapter":"service.set","args":{"name":"sshd.service","desired_state":"started"}}]}`
	f := newReadFixture(t, obsEnabledRunning, statusJSON)

	cfg := defaultConfig()
	cfg.DenyNames = []string{"sshd"}
	view, rej := txRollback(cfg, rollbackIn{TxID: txID})
	if rej == nil {
		t.Fatalf("第三档目标应被拒, 实际返回 %+v", view)
	}
	if rej.Error != codeRollbackDenied || rej.Tier != string(autonomy.TierHuman) || rej.Outcome != "denied" {
		t.Fatalf("rej = %+v", rej)
	}
	if rej.TxID != txID {
		t.Fatalf("rej.tx_id = %q", rej.TxID)
	}

	calls := readCalls(t, f.calls)
	if hasCall(calls, "rollback") {
		t.Fatalf("第三档拒绝后仍调用了 rollback: %q", calls)
	}
	if !hasCall(calls, "status "+txID) {
		t.Fatalf("判定前应读 journal: %q", calls)
	}

	lines := readAuditLines(t, f.auditLog)
	found := false
	for _, line := range lines {
		if line.Tool == toolRollback && line.Outcome == "denied" {
			found = true
			if line.Args["tier"] != string(autonomy.TierHuman) {
				t.Fatalf("审计 tier = %v", line.Args["tier"])
			}
		}
	}
	if !found {
		t.Fatalf("缺 tx_rollback denied 审计: %+v", lines)
	}
}

// 非第三档目标按正常回滚执行,结果里带重新判定的 tier。
func TestTxRollbackExecutesWhenTargetIsNotHuman(t *testing.T) {
	txID := "0123456789abcdef"
	statusJSON := `{"id":"` + txID + `","created_at":"2026-11-20T10:00:00Z","status":"applied",` +
		`"steps":[{"index":0,"adapter":"service.set","args":{"name":"demo.service","desired_state":"started"}}]}`
	f := newReadFixture(t, obsEnabledRunning, statusJSON)

	view, rej := txRollback(defaultConfig(), rollbackIn{TxID: txID})
	if rej != nil {
		t.Fatalf("期望执行, 收到拒绝 %+v", rej)
	}
	if view.TxID != txID || view.Outcome != "rolled_back" || view.Tier != string(autonomy.TierConfirm) {
		t.Fatalf("view = %+v", view)
	}
	if !hasCall(readCalls(t, f.calls), "rollback "+txID) {
		t.Fatal("未调用 rollback 子命令")
	}
}

// 空事务没有可判定的目标作用域:拒绝而不是把"无目标"当"自动通过"。
func TestTxRollbackRejectsTransactionWithoutTargets(t *testing.T) {
	txID := "0123456789abcdef"
	statusJSON := `{"id":"` + txID + `","created_at":"2026-11-20T10:00:00Z","status":"proposed","steps":[]}`
	f := newReadFixture(t, obsEnabledRunning, statusJSON)

	_, rej := txRollback(defaultConfig(), rollbackIn{TxID: txID})
	if rej == nil || rej.Error != codeNothingToRollback {
		t.Fatalf("rej = %+v", rej)
	}
	if hasCall(readCalls(t, f.calls), "rollback") {
		t.Fatal("无目标时不应调用 rollback")
	}
}

// 非 service.set 步骤无法重建作用域:fail-closed,不猜、不调用 rollback。
func TestTxRollbackRejectsUnsupportedStepAdapter(t *testing.T) {
	txID := "0123456789abcdef"
	statusJSON := `{"id":"` + txID + `","created_at":"2026-11-20T10:00:00Z","status":"applied",` +
		`"steps":[{"index":0,"adapter":"package.set","args":{"name":"nginx"}}]}`
	f := newReadFixture(t, obsEnabledRunning, statusJSON)

	_, rej := txRollback(defaultConfig(), rollbackIn{TxID: txID})
	if rej == nil || rej.Error != codeUnsupportedRollbackTarget {
		t.Fatalf("rej = %+v", rej)
	}
	if hasCall(readCalls(t, f.calls), "rollback") {
		t.Fatal("未知目标时不应调用 rollback")
	}
}

// 走真实 MCP 会话确认四个工具已接线(不再返回占位错误)。
func TestReadToolsThroughMCPSession(t *testing.T) {
	txID := "0123456789abcdef"
	statusJSON := `{"id":"` + txID + `","created_at":"2026-11-20T10:00:00Z","status":"applied","steps":[]}`
	f := newReadFixture(t, obsEnabledRunning, statusJSON)
	if err := os.MkdirAll(f.pending, 0o755); err != nil {
		t.Fatal(err)
	}

	session, closeSession := connectTestSession(t, defaultConfig())
	defer closeSession()

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "tx_status",
		Arguments: map[string]any{"tx_id": txID},
	})
	if err != nil {
		t.Fatalf("CallTool tx_status: %v", err)
	}
	if res.IsError {
		t.Fatalf("tx_status 失败: %+v", res.Content)
	}
	var status statusView
	if err := json.Unmarshal([]byte(toolResultText(t, res)), &status); err != nil {
		t.Fatalf("tx_status 返回不是 JSON: %v", err)
	}
	if status.TxID != txID || status.State != "applied" {
		t.Fatalf("status = %+v", status)
	}

	res, err = session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "tx_pending",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool tx_pending: %v", err)
	}
	if res.IsError {
		t.Fatalf("tx_pending 失败: %+v", res.Content)
	}
	var pending pendingView
	if err := json.Unmarshal([]byte(toolResultText(t, res)), &pending); err != nil {
		t.Fatalf("tx_pending 返回不是 JSON: %v", err)
	}
	if len(pending.Items) != 0 {
		t.Fatalf("pending = %+v", pending.Items)
	}
}

// toolResultText 取单文本块的正文。
func toolResultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("期望单文本块, 收到 %d 块", len(res.Content))
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("内容类型 = %T", res.Content[0])
	}
	return text.Text
}
