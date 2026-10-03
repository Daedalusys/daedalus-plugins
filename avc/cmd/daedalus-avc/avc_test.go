// avc 只读解析与外部 CLI 编排的单测:fixture 驱动的 ausearch --format default
// 解析、参数校验、降级、退出码语义与真 exec 贯通。
//
// 数据源固定指向包内 testdata/ 的 ausearch / audit2why / audit2allow 输出夹具;
// 外部 CLI 一律经 execRunner 注入替身或临时假脚本,测试零触碰宿主
// /var/log/audit。唯一例外是 TestRunAusearch_Real* 系列走真 fork 验证
// stderr/退出码管道(仍不读真实审计日志)。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixtureDir 是 testdata/ 的相对路径,测试在包目录内执行。
const fixtureDir = "testdata"

// fixturePath 返回夹具的绝对路径(真 exec 段假脚本需要绝对路径)。
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("解析夹具绝对路径失败: %v", err)
	}
	return abs
}

// loadFixture 读 testdata 下文本夹具。
func loadFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("读夹具 %s 失败: %v", name, err)
	}
	return string(b)
}

// fakeRunner 是 execRunner 夹具:把 lines 逐行喂给 onLine;onLine 返回 false 时
// 记录 aborted 并原地返回(模拟提前 kill 收工)。err 非 nil 时在 lines 喂完后
// 返回(可能是 execError / fs.PathError,用于模拟退出码与缺失二进制)。
// stdin 非 nil 时读到 f.stdin(校验 audit2why / audit2allow 拿到的事件记录)。
type fakeRunner struct {
	lines   [][]byte
	err     error
	aborted bool
	args    []string
	stdin   []byte
}

func (f *fakeRunner) run(_ context.Context, _ string, stdin io.Reader, onLine func([]byte) bool, args ...string) error {
	if stdin != nil {
		b, _ := io.ReadAll(stdin)
		f.stdin = append([]byte(nil), b...)
	}
	f.args = append([]string(nil), args...)
	for _, line := range f.lines {
		if !onLine(line) {
			f.aborted = true
			return nil
		}
	}
	if f.err != nil {
		return f.err
	}
	return nil
}

// newFakeService 装配一个挂 fakeRunner 的 service(占位 runner = newService())。
func newFakeService(lines ...[]byte) (*service, *fakeRunner) {
	fr := &fakeRunner{lines: lines}
	return &service{run: fr.run, timeout: avcTimeout}, fr
}

// splitFixture 把 --format default 夹具按行拆分,模拟 stdout 逐行回传。
func splitFixture(t *testing.T, name string) [][]byte {
	t.Helper()
	content := loadFixture(t, name)
	var out [][]byte
	for _, line := range strings.Split(content, "\n") {
		out = append(out, []byte(line))
	}
	return out
}

// --- 解析层 ---

// TestParseAvcEvents_Standard 标准 3 事件夹具必须解析出 3 条记录,字段齐全。
func TestParseAvcEvents_Standard(t *testing.T) {
	lines := splitFixture(t, "ausearch-3events.txt")
	got := parseAvcEvents(lines)
	if len(got) != 3 {
		t.Fatalf("解析得 %d 条事件, want 3", len(got))
	}
	first := got[0]
	if first.EventID != "42" {
		t.Errorf("EventID=%q, want 42", first.EventID)
	}
	if first.Type != "AVC" {
		t.Errorf("Type=%q, want AVC", first.Type)
	}
	if first.SContext != "system_u:system_r:httpd_t:s0" {
		t.Errorf("SContext=%q", first.SContext)
	}
	if first.TContext != "system_u:object_r:shadow_t:s0" {
		t.Errorf("TContext=%q", first.TContext)
	}
	if first.TClass != "file" {
		t.Errorf("TClass=%q", first.TClass)
	}
	if first.Perm != "read" {
		t.Errorf("Perm=%q", first.Perm)
	}
	if first.Comm != "httpd" {
		t.Errorf("Comm=%q", first.Comm)
	}
	if first.PID != "1234" {
		t.Errorf("PID=%q", first.PID)
	}
	if first.Permissive != false {
		t.Errorf("Permissive=%v", first.Permissive)
	}
	third := got[2]
	if third.Type != "USER_AVC" {
		t.Errorf("第三条 Type=%q, want USER_AVC", third.Type)
	}
	if third.TClass != "tcp_socket" {
		t.Errorf("第三条 TClass=%q", third.TClass)
	}
}

// TestParseAvcEvents_EmptyNoMatch 只有 <no matches> 头的输入 → 0 条事件。
func TestParseAvcEvents_EmptyNoMatch(t *testing.T) {
	lines := splitFixture(t, "ausearch-no-matches.txt")
	got := parseAvcEvents(lines)
	if len(got) != 0 {
		t.Fatalf("no-match 应解析出 0 条, got %d", len(got))
	}
}

// TestParseAvcEvents_PermissiveFlag permissive=1 时必须置位。
func TestParseAvcEvents_PermissiveFlag(t *testing.T) {
	lines := [][]byte{
		[]byte("----"),
		[]byte("time->Tue Nov  7 00:13:20 2023"),
		[]byte(`type=AVC msg=audit(1699287200.123:50): avc:  denied  { read } for  pid=1 comm="foo" name="x" dev="sda1" ino=1 scontext=u:r:t:s0 tcontext=u:object_r:tt:s0 tclass=file permissive=1`),
	}
	got := parseAvcEvents(lines)
	if len(got) != 1 {
		t.Fatalf("应解析出 1 条, got %d", len(got))
	}
	if !got[0].Permissive {
		t.Errorf("permissive=1 应置位")
	}
}

// TestParseAvcEvents_BadLineSkipped 坏行必须跳过不崩。
func TestParseAvcEvents_BadLineSkipped(t *testing.T) {
	lines := [][]byte{
		[]byte("----"),
		[]byte("time->garbage"),
		[]byte("not a valid avc line"),
		[]byte(""),
		[]byte("----"),
		[]byte("time->Tue Nov  7 00:13:20 2023"),
		[]byte(`type=AVC msg=audit(1699287200.123:50): avc:  denied  { read } for  pid=1 comm="foo" name="x" dev="sda1" ino=1 scontext=u:r:t:s0 tcontext=u:object_r:tt:s0 tclass=file permissive=0`),
	}
	got := parseAvcEvents(lines)
	if len(got) != 1 {
		t.Errorf("坏行应跳过,保留 1 条好行, got %d", len(got))
	}
}

// --- 载荷 JSON 形态 ---

func TestResultsStructs_JSONShape(t *testing.T) {
	ev := AVCEvent{EventID: "42", Type: "AVC"}
	if b := mustJSON(t, ev); !strings.Contains(b, `"event_id":"42"`) {
		t.Errorf("AVCEvent JSON 缺 event_id: %s", b)
	}
	br := SummaryBucket{Key: "a|b|c|d", Count: 3}
	if b := mustJSON(t, br); !strings.Contains(b, `"key":"a|b|c|d"`) {
		t.Errorf("SummaryBucket JSON 缺 key: %s", b)
	}
	ex := Explanation{EventID: "42", Reason: "r", Suggestion: "s"}
	if b := mustJSON(t, ex); !strings.Contains(b, `"event_id":"42"`) {
		t.Errorf("Explanation JSON 缺 event_id: %s", b)
	}
}

// --- 入参校验 ---

// TestRecentArgsValidation 校验 since 格式 / limit 边界 / offset 边界。
func TestRecentArgsValidation(t *testing.T) {
	cases := []struct {
		name    string
		args    RecentArgs
		wantErr bool
	}{
		{"ok default", RecentArgs{}, false},
		{"ok today", RecentArgs{Since: ptrStr("today")}, false},
		{"ok yesterday", RecentArgs{Since: ptrStr("yesterday")}, false},
		{"ok recent", RecentArgs{Since: ptrStr("recent")}, false},
		{"ok date", RecentArgs{Since: ptrStr("2026-10-02")}, false},
		{"ok datetime", RecentArgs{Since: ptrStr("2026-10-02 10:00:00")}, false},
		{"bad since injection", RecentArgs{Since: ptrStr("--help; rm -rf /")}, true},
		{"bad since space-prefix", RecentArgs{Since: ptrStr("  --all")}, true},
		{"bad limit zero", RecentArgs{Limit: ptrInt(0)}, true},
		{"bad limit overflow", RecentArgs{Limit: ptrInt(avcMaxLimit + 1)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.args.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("应报错, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("不应报错, got %v", err)
			}
		})
	}
}

// TestExplainArgsValidation 校验 event_id 形态注入拒绝。
func TestExplainArgsValidation(t *testing.T) {
	cases := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"ok", "42", false},
		{"ok long", "1699287200:42", false},
		{"empty", "", true},
		{"injection shell", "42; rm -rf /", true},
		{"injection flag", "--help", true},
		{"traversal", "../etc/passwd", true},
		{"letters", "abc", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (&ExplainArgs{EventID: tc.id}).Validate()
			if tc.wantErr && err == nil {
				t.Errorf("应报错, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("不应报错, got %v", err)
			}
		})
	}
}

// TestSummaryArgsValidation 汇总同样校验 since。
func TestSummaryArgsValidation(t *testing.T) {
	if err := (&SummaryArgs{Since: ptrStr("today")}).Validate(); err != nil {
		t.Errorf("合法 since 应通过: %v", err)
	}
	if err := (&SummaryArgs{Since: ptrStr("$(reboot)")}).Validate(); err == nil {
		t.Errorf("注入 since 应拒绝")
	}
}

// --- service 层(注入 fakeRunner)---

// TestRecent_3EventsParsesAndPages 注入 3 事件夹具 → 3 条;limit=2 → 截断。
func TestRecent_3EventsParsesAndPages(t *testing.T) {
	lines := splitFixture(t, "ausearch-3events.txt")
	svc, fr := newFakeService(lines...)
	limit := 2
	res, err := svc.Recent(context.Background(), RecentArgs{Limit: &limit})
	if err != nil {
		t.Fatalf("Recent 失败: %v", err)
	}
	if res.TotalLines != 3 {
		t.Errorf("TotalLines=%d, want 3", res.TotalLines)
	}
	if res.Returned != 2 {
		t.Errorf("Returned=%d, want 2", res.Returned)
	}
	if !res.Truncated {
		t.Errorf("limit=2 时应 Truncated")
	}
	if !strings.Contains(res.Note, "limit") {
		t.Errorf("Note 应含截断提示: %q", res.Note)
	}
	if !strings.Contains(strings.Join(fr.args, " "), "-m avc,user_avc") {
		t.Errorf("argv 应含 -m avc,user_avc: %v", fr.args)
	}
}

// TestRecent_EmptyNoMatchIsEmpty 合法空结果(无匹配)必须 0 条 + note,不报错。
func TestRecent_EmptyNoMatchIsEmpty(t *testing.T) {
	lines := splitFixture(t, "ausearch-no-matches.txt")
	svc, fr := newFakeService(lines...)
	fr.err = &execError{Code: 1, Stderr: "<no matches>\n"}
	res, err := svc.Recent(context.Background(), RecentArgs{})
	if err != nil {
		t.Fatalf("无匹配不应报错: %v", err)
	}
	if len(res.Events) != 0 {
		t.Errorf("应为 0 条, got %d", len(res.Events))
	}
	if res.Note == "" {
		t.Errorf("空结果应带 note")
	}
	if !strings.Contains(res.Note, "无匹配") {
		t.Errorf("note 应含'无匹配', got %q", res.Note)
	}
}

// TestRecent_AuditdNotEnabled empty + audit log EACCES stderr → 优雅降级。
func TestRecent_AuditdNotEnabled(t *testing.T) {
	svc, fr := newFakeService()
	fr.err = &execError{Code: 1, Stderr: "Error opening /var/log/audit/audit.log (权限不够)\n"}
	res, err := svc.Recent(context.Background(), RecentArgs{})
	if err != nil {
		t.Fatalf("审计日志不可读不应报错: %v", err)
	}
	if len(res.Events) != 0 {
		t.Errorf("应为 0 条, got %d", len(res.Events))
	}
	if !strings.Contains(res.Note, "auditd") && !strings.Contains(res.Note, "审计") {
		t.Errorf("note 应说明审计不可用: %q", res.Note)
	}
}

// TestRecent_MissingBinaryInjected 缺 ausearch → 空集 + note,不 panic。
func TestRecent_MissingBinaryInjected(t *testing.T) {
	svc, fr := newFakeService()
	fr.err = &fs.PathError{Op: "exec", Path: ausearchBinary, Err: fs.ErrNotExist}
	res, err := svc.Recent(context.Background(), RecentArgs{})
	if err != nil {
		t.Fatalf("缺 binary 不应报错: %v", err)
	}
	if len(res.Events) != 0 {
		t.Errorf("应为 0 条, got %d", len(res.Events))
	}
	if res.Note == "" {
		t.Errorf("缺 binary 应带 note")
	}
}

// TestRecent_RealErrorPropagated rc≥2 → 真错误上抛。
func TestRecent_RealErrorPropagated(t *testing.T) {
	svc, fr := newFakeService()
	fr.err = &execError{Code: 3, Stderr: "cannot open config\n"}
	_, err := svc.Recent(context.Background(), RecentArgs{})
	if err == nil {
		t.Fatalf("rc=3 应上抛")
	}
	if !strings.Contains(err.Error(), "cannot open config") {
		t.Errorf("错误应含 stderr: %q", err.Error())
	}
}

// TestExplain_FullPipeline 注入 ausearch → audit2why → audit2allow,字段齐全。
func TestExplain_FullPipeline(t *testing.T) {
	record := `type=AVC msg=audit(1699287200.123:42): avc:  denied  { read } for  pid=1234 comm="httpd" name="shadow" dev="sda1" ino=12345 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0`
	whyOut := strings.Split(loadFixture(t, "audit2why-one.txt"), "\n")
	allowOut := strings.Split(loadFixture(t, "audit2allow-explain-one.txt"), "\n")

	// 三段管线:ausearch → audit2why → audit2allow --explain
	svc, _ := newFakeService()
	pipeline := runFakeExplainPipeline(record, whyOut, allowOut)
	svc.run = pipeline.run

	res, err := svc.Explain(context.Background(), ExplainArgs{EventID: "42"})
	if err != nil {
		t.Fatalf("Explain 失败: %v", err)
	}
	if res.EventID != "42" {
		t.Errorf("EventID=%q", res.EventID)
	}
	if !strings.Contains(res.Reason, "Missing type enforcement") {
		t.Errorf("Reason 应含 audit2why 语义: %q", res.Reason)
	}
	if !strings.Contains(res.Suggestion, "allow httpd_t shadow_t:file") {
		t.Errorf("Suggestion 应含 audit2allow 规则: %q", res.Suggestion)
	}
	if res.Note != "" {
		t.Errorf("无降级时 Note 应为空: %q", res.Note)
	}
}

// TestExplain_EventNotFound ausearch 无匹配 → 优雅降级 note,不报错。
func TestExplain_EventNotFound(t *testing.T) {
	svc, fr := newFakeService()
	fr.err = &execError{Code: 1, Stderr: "<no matches>\n"}
	res, err := svc.Explain(context.Background(), ExplainArgs{EventID: "42"})
	if err != nil {
		t.Fatalf("未匹配不应报错: %v", err)
	}
	if res.Note == "" {
		t.Errorf("未匹配应带 note")
	}
	if res.Reason != "" {
		t.Errorf("未匹配不应有 Reason: %q", res.Reason)
	}
}

// TestExplain_MissingAudit2Why audit2why 缺失 → Reason 降级 note,Suggestion 仍可填。
func TestExplain_MissingAudit2Why(t *testing.T) {
	svc, _ := newFakeService()
	svc.run = func(ctx context.Context, bin string, _ io.Reader, onLine func([]byte) bool, args ...string) error {
		// ausearch 正常,audit2why 缺失
		if strings.Contains(bin, "ausearch") {
			onLine([]byte(`type=AVC msg=audit(1699287200.123:42): avc:  denied  { read } for  pid=1234 comm="httpd" scontext=u:r:t:s0 tcontext=u:object_r:tt:s0 tclass=file permissive=0`))
			return nil
		}
		if strings.Contains(bin, "audit2why") {
			return &fs.PathError{Op: "exec", Path: audit2whyBinary, Err: fs.ErrNotExist}
		}
		// audit2allow 可用,但输入仍需喂回 audit2why 输出
		onLine([]byte("allow u:r:t:s0 u:object_r:tt:s0:file read;"))
		return nil
	}
	res, err := svc.Explain(context.Background(), ExplainArgs{EventID: "42"})
	if err != nil {
		t.Fatalf("audit2why 缺失不应报错: %v", err)
	}
	if !strings.Contains(res.Note, "audit2why") {
		t.Errorf("Note 应说明 audit2why 缺失: %q", res.Note)
	}
}

// TestEventSerial_BareID 纯数字输入原样返回。
func TestEventSerial_BareID(t *testing.T) {
	got, err := eventSerial("42")
	if err != nil || got != "42" {
		t.Errorf("eventSerial(\"42\")=%q,%v, want \"42\",nil", got, err)
	}
}

// TestEventSerial_EpochColonSerial "epoch:serial" 必须剥成 serial 后段。
func TestEventSerial_EpochColonSerial(t *testing.T) {
	got, err := eventSerial("1699287200:42")
	if err != nil || got != "42" {
		t.Errorf("eventSerial(\"1699287200:42\")=%q,%v, want \"42\",nil", got, err)
	}
}

// TestEventSerial_RejectsNonNumericTail 尾段非数字应被 eventSerial 直接拒绝
// (防御性:即使 eventIDPattern 已先于 Validate 拒绝,eventSerial 自身仍要兜底)。
func TestEventSerial_RejectsNonNumericTail(t *testing.T) {
	if _, err := eventSerial("1699287200:abc"); err == nil {
		t.Errorf("eventSerial 非数字尾段应拒绝")
	}
	if _, err := eventSerial(":"); err == nil {
		t.Errorf("eventSerial 仅冒号应拒绝")
	}
	if err := (&ExplainArgs{EventID: "1699287200:abc"}).Validate(); err == nil {
		t.Errorf("eventIDPattern 应拒绝非数字尾段")
	}
}

// TestExplain_EventIDSerialNormalization "epoch:serial" → argv -a serial 段;
// 不应静默搜 id=epoch。
func TestExplain_EventIDSerialNormalization(t *testing.T) {
	svc, _ := newFakeService()
	// ausearch 喂一条记录让阶段 1 通过;audit2why/audit2allow 返回空即可。
	// 用闭包捕获 ausearch 的 argv 供断言。
	var ausearchArgs []string
	svc.run = func(_ context.Context, bin string, _ io.Reader, onLine func([]byte) bool, args ...string) error {
		if strings.Contains(bin, "ausearch") {
			ausearchArgs = append([]string(nil), args...)
			onLine([]byte(`type=AVC msg=audit(1699287200.123:42): avc:  denied  { read } for  pid=1234 comm="httpd" scontext=u:r:t:s0 tcontext=u:object_r:tt:s0 tclass=file permissive=0`))
		}
		return nil
	}
	if _, err := svc.Explain(context.Background(), ExplainArgs{EventID: "1699287200:42"}); err != nil {
		t.Fatalf("Explain 失败: %v", err)
	}
	joined := strings.Join(ausearchArgs, " ")
	if !strings.Contains(joined, "-a 42") {
		t.Errorf("argv 应为 -a 42(剥 serial), got %v", ausearchArgs)
	}
	if strings.Contains(joined, "-a 1699287200:42") {
		t.Errorf("argv 不得直喂 epoch:serial, got %v", ausearchArgs)
	}
}

// TestExplain_BackendRc2DegradesWithNote I2:audit2why rc≥2 不得静默,也不得
// 毁掉主结果——note 具名后端 + 错误,保留事件本体,第 3 段仍继续。
func TestExplain_BackendRc2DegradesWithNote(t *testing.T) {
	svc, _ := newFakeService()
	svc.run = func(_ context.Context, bin string, _ io.Reader, onLine func([]byte) bool, _ ...string) error {
		switch {
		case strings.Contains(bin, "ausearch"):
			onLine([]byte(`type=AVC msg=audit(1699287200.123:42): avc:  denied  { read } for  pid=1234 comm="httpd" scontext=u:r:t:s0 tcontext=u:object_r:tt:s0 tclass=file permissive=0`))
			return nil
		case strings.Contains(bin, "audit2why"):
			return &execError{Code: 2, Stderr: "audit2why internal failure"}
		default: // audit2allow 仍可用
			onLine([]byte("allow u:r:t:s0 u:object_r:tt:s0:file read;"))
			return nil
		}
	}
	res, err := svc.Explain(context.Background(), ExplainArgs{EventID: "42"})
	if err != nil {
		t.Fatalf("可选后端 rc≥2 应降级不应报错: %v", err)
	}
	if !strings.Contains(res.Note, "audit2why") {
		t.Errorf("note 应具名 audit2why, got %q", res.Note)
	}
	if res.Suggestion == "" {
		t.Errorf("audit2why 失败不应阻断第 3 段, Suggestion 应保留")
	}
	if res.EventID != "42" {
		t.Errorf("事件本体 EventID 应保留, got %q", res.EventID)
	}
}

// TestExplain_BackendRc2SecondStage I2 对称:audit2allow rc≥2 具名降级,
// audit2why 的 Reason 保留。
func TestExplain_BackendRc2SecondStage(t *testing.T) {
	svc, _ := newFakeService()
	svc.run = func(_ context.Context, bin string, _ io.Reader, onLine func([]byte) bool, _ ...string) error {
		switch {
		case strings.Contains(bin, "ausearch"):
			onLine([]byte(`type=AVC msg=audit(1699287200.123:42): avc:  denied  { read } for  pid=1234 comm="httpd" scontext=u:r:t:s0 tcontext=u:object_r:tt:s0 tclass=file permissive=0`))
			return nil
		case strings.Contains(bin, "audit2why"):
			onLine([]byte("Was caused by: Missing type enforcement"))
			return nil
		default:
			return &execError{Code: 2, Stderr: "audit2allow internal failure"}
		}
	}
	res, err := svc.Explain(context.Background(), ExplainArgs{EventID: "42"})
	if err != nil {
		t.Fatalf("可选后端 rc≥2 应降级不应报错: %v", err)
	}
	if !strings.Contains(res.Note, "audit2allow") {
		t.Errorf("note 应具名 audit2allow, got %q", res.Note)
	}
	if !strings.Contains(res.Reason, "Missing type enforcement") {
		t.Errorf("audit2allow 失败不应抹掉 Reason: %q", res.Reason)
	}
}

// TestSummary_AggregationByBuckets 3 事件按 (scontext|tclass|comm|perm) 分组。
func TestSummary_AggregationByBuckets(t *testing.T) {
	lines := splitFixture(t, "ausearch-3events.txt")
	svc, _ := newFakeService(lines...)
	res, err := svc.Summary(context.Background(), SummaryArgs{})
	if err != nil {
		t.Fatalf("Summary 失败: %v", err)
	}
	if res.Total != 3 {
		t.Errorf("Total=%d, want 3", res.Total)
	}
	if len(res.Buckets) == 0 {
		t.Fatalf("Buckets 应非空")
	}
	// 3 个事件的 (scontext|tclass|comm|perm) 应生成 3 个不同桶
	seen := map[string]bool{}
	for _, b := range res.Buckets {
		if seen[b.Key] {
			t.Errorf("Bucket 重复: %q", b.Key)
		}
		seen[b.Key] = true
	}
	if len(seen) != 3 {
		t.Errorf("应有 3 个不同桶, got %d", len(seen))
	}
}

// TestSummary_AggregationWithDuplicates 同 key 多事件 → count>1。
func TestSummary_AggregationWithDuplicates(t *testing.T) {
	lines := [][]byte{
		[]byte("----"),
		[]byte("time->Tue Nov  7 00:13:20 2023"),
		[]byte(`type=AVC msg=audit(1699287200.123:50): avc:  denied  { read } for  pid=1 comm="foo" scontext=u:r:t:s0 tcontext=u:object_r:tt:s0 tclass=file permissive=0`),
		[]byte("----"),
		[]byte("time->Tue Nov  7 00:13:20 2023"),
		[]byte(`type=AVC msg=audit(1699287200.123:51): avc:  denied  { read } for  pid=2 comm="foo" scontext=u:r:t:s0 tcontext=u:object_r:tt:s0 tclass=file permissive=0`),
	}
	svc, _ := newFakeService(lines...)
	res, err := svc.Summary(context.Background(), SummaryArgs{})
	if err != nil {
		t.Fatalf("Summary 失败: %v", err)
	}
	if res.Total != 2 {
		t.Errorf("Total=%d, want 2", res.Total)
	}
	if len(res.Buckets) != 1 {
		t.Fatalf("应 1 个桶, got %d", len(res.Buckets))
	}
	if res.Buckets[0].Count != 2 {
		t.Errorf("Count=%d, want 2", res.Buckets[0].Count)
	}
}

// TestSummary_EmptyIsEmpty + note。
func TestSummary_EmptyIsEmpty(t *testing.T) {
	svc, fr := newFakeService()
	fr.err = &execError{Code: 1, Stderr: "<no matches>\n"}
	res, err := svc.Summary(context.Background(), SummaryArgs{})
	if err != nil {
		t.Fatalf("Summary 空不应报错: %v", err)
	}
	if res.Total != 0 {
		t.Errorf("Total=%d, want 0", res.Total)
	}
	if len(res.Buckets) != 0 {
		t.Errorf("Buckets 应 []: %d", len(res.Buckets))
	}
	if res.Note == "" {
		t.Errorf("空结果应带 note")
	}
}

// --- 真 exec 贯通(TestRunAusearch_Real*)---

// writeFakeScript 写一个可执行的 shell 假脚本到 tmp 目录,返回绝对路径。
func writeFakeScript(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("写假脚本失败: %v", err)
	}
	return path
}

// TestRunAusearch_RealStderrBeforeStart 真 fork:rc=1 + stderr 必须进 execError.Stderr
// (承接 journal/integrity 教训:cmd.Stderr 必须在 Start 前接好,否则永远空)。
func TestRunAusearch_RealStderrBeforeStart(t *testing.T) {
	path := writeFakeScript(t, "ausearch", "#!/bin/sh\necho 'Error opening log (X)' >&2\nexit 1\n")
	got := runCLI(context.Background(), path, func([]byte) bool { return true }, "-m", "avc")
	if got == nil {
		t.Fatal("rc=1 应返回 execError 而非 nil")
	}
	var ee *execError
	if !errors.As(got, &ee) {
		t.Fatalf("err 应为 *execError, got %T: %v", got, got)
	}
	if ee.Code != 1 {
		t.Errorf("Code=%d, want 1", ee.Code)
	}
	if !strings.Contains(ee.Stderr, "Error opening log (X)") {
		t.Errorf("Stderr 应含 stderr 文本: %q", ee.Stderr)
	}
}

// TestRunAusearch_RealRc2Stderr 真 fork:rc=2 + stderr 必须 wrap。
func TestRunAusearch_RealRc2Stderr(t *testing.T) {
	path := writeFakeScript(t, "ausearch", "#!/bin/sh\necho 'cannot open config' >&2\nexit 2\n")
	got := runCLI(context.Background(), path, func([]byte) bool { return true }, "-m", "avc")
	if got == nil {
		t.Fatal("rc=2 应返回 execError")
	}
	var ee *execError
	if !errors.As(got, &ee) {
		t.Fatalf("err 应为 *execError, got %T: %v", got, got)
	}
	if ee.Code != 2 {
		t.Errorf("Code=%d, want 2", ee.Code)
	}
	if !strings.Contains(ee.Stderr, "cannot open config") {
		t.Errorf("Stderr 应含文本: %q", ee.Stderr)
	}
}

// TestRunAusearch_RealStdoutCaptured 真 fork:rc=0 时 stdout 逐行回传;
// onLine=false 触发 early-kill。
func TestRunAusearch_RealStdoutCaptured(t *testing.T) {
	path := writeFakeScript(t, "ausearch", "#!/bin/sh\nfor i in 1 2 3 4 5; do echo \"line $i\"; done\n")
	var got []string
	_ = runCLI(context.Background(), path, func(b []byte) bool {
		got = append(got, string(b))
		return len(got) < 2
	}, "-m", "avc")
	if len(got) != 2 {
		t.Errorf("onLine=false 应提前杀子进程, got %d 行", len(got))
	}
}

// TestRunAusearch_RealCtxDeadline ctx 到期优先返回 ctx.Err()(DeadlineExceeded)。
func TestRunAusearch_RealCtxDeadline(t *testing.T) {
	path := writeFakeScript(t, "ausearch", "#!/bin/sh\nexec sleep 5\n")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	got := runCLI(ctx, path, func([]byte) bool { return true }, "-m", "avc")
	if !errors.Is(got, context.DeadlineExceeded) {
		t.Errorf("ctx 到期应返回 DeadlineExceeded, got %v", got)
	}
}

// TestRunAusearch_RealMissingBinary 真 fork:binary 缺失应 wrap 为 fs.ErrNotExist,
// isMissingBinary 可识别。
func TestRunAusearch_RealMissingBinary(t *testing.T) {
	got := runCLI(context.Background(), filepath.Join(t.TempDir(), "no-such-bin"), func([]byte) bool { return true }, "-m", "avc")
	if !isMissingBinary(got) {
		t.Errorf("缺失 binary 应被 isMissingBinary 识别, got %v", got)
	}
}

// TestExecHelper_RealStdinFed 真 fork:execHelper 的 stdin 必须实喂给子进程
// (audit2why / audit2allow 依赖 ausearch 记录经 stdin 传入);runCLI 包装则
// 恒 nil stdin。
func TestExecHelper_RealStdinFed(t *testing.T) {
	path := writeFakeScript(t, "cat", "#!/bin/sh\ncat\n")
	var got []string
	if err := execHelper(context.Background(), path, strings.NewReader("type=AVC msg=audit(1:2)\n"), func(b []byte) bool {
		got = append(got, string(b))
		return true
	}); err != nil {
		t.Fatalf("execHelper 失败: %v", err)
	}
	if len(got) != 1 || !strings.Contains(got[0], "type=AVC") {
		t.Errorf("stdin 未被实喂给子进程, got %q", got)
	}
}

// TestExecHelper_RealStdinStderr 真 fork:带 stdin 时 stderr 仍须在
// cmd.Start() 前接好(承接 journal/integrity 教训),否则 execError.Stderr 恒空。
func TestExecHelper_RealStdinStderr(t *testing.T) {
	path := writeFakeScript(t, "audit2why", "#!/bin/sh\ncat >/dev/null\necho 'why failed' >&2\nexit 2\n")
	got := execHelper(context.Background(), path, strings.NewReader("x\n"), func([]byte) bool { return true })
	var ee *execError
	if !errors.As(got, &ee) {
		t.Fatalf("err 应为 *execError, got %T: %v", got, got)
	}
	if ee.Code != 2 || !strings.Contains(ee.Stderr, "why failed") {
		t.Errorf("stdin 态 stderr 应被捕获, code=%d stderr=%q", ee.Code, ee.Stderr)
	}
}

// --- handleExecError 语义收敛 ---

// TestHandleExecError 分类 ausearch 的退出码与 stderr 模式。
func TestHandleExecError(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantFatal bool
		wantNote  bool
	}{
		{"nil", nil, false, false},
		{"missing binary", &fs.PathError{Op: "exec", Path: "x", Err: fs.ErrNotExist}, false, true},
		{"no match rc=1", &execError{Code: 1, Stderr: "<no matches>"}, false, true},
		{"log missing rc=1", &execError{Code: 1, Stderr: "Error opening /var/log/audit/audit.log (X)"}, false, true},
		{"config missing rc=1", &execError{Code: 1, Stderr: "Error opening config file (X)"}, false, true},
		{"fatal rc=3", &execError{Code: 3, Stderr: "boom"}, true, false},
		{"non-execError", errors.New("boom"), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			note, fatal := handleExecError(tc.err)
			if fatal != tc.wantFatal {
				t.Errorf("fatal=%v, want %v", fatal, tc.wantFatal)
			}
			if tc.wantNote && note == "" {
				t.Errorf("应产生 note")
			}
			if !tc.wantNote && note != "" {
				t.Errorf("不应产生 note, got %q", note)
			}
		})
	}
}

// TestHandleExecError_AuditdWinsOverNoMatch 同现 "审计日志不可读" + "<no matches>"
// 时,必须返回 auditd 不可用语义——后者掩盖前者会让运维错失更可行动的提示。
func TestHandleExecError_AuditdWinsOverNoMatch(t *testing.T) {
	err := &execError{Code: 1, Stderr: "Error opening /var/log/audit/audit.log (权限不够)\n<no matches>\n"}
	note, fatal := handleExecError(err)
	if fatal {
		t.Fatalf("rc=1 不应 fatal")
	}
	if !strings.Contains(note, "auditd") && !strings.Contains(note, "审计") {
		t.Errorf("note 应为 auditd 不可用语义, got %q", note)
	}
	if strings.Contains(note, "无匹配") {
		t.Errorf("no-match 不得掩盖 auditd 不可用, got %q", note)
	}
}

// TestIsAusearchNoMatch 区分 no-match 与真实错误。
func TestIsAusearchNoMatch(t *testing.T) {
	if !isAusearchNoMatch(&execError{Code: 1, Stderr: "<no matches>\n"}) {
		t.Errorf("no-match 应识别")
	}
	if isAusearchNoMatch(&execError{Code: 1, Stderr: "Error opening /var/log/audit/audit.log\n"}) {
		t.Errorf("log 打不开不是 no-match")
	}
	if isAusearchNoMatch(nil) {
		t.Errorf("nil 不应是 no-match")
	}
}

// TestIsAuditLogUnavailable 识别"审计日志不可读"降级。
func TestIsAuditLogUnavailable(t *testing.T) {
	if !isAuditLogUnavailable(&execError{Code: 1, Stderr: "Error opening /var/log/audit/audit.log (X)"}) {
		t.Errorf("log EACCES 应识别")
	}
	if !isAuditLogUnavailable(&execError{Code: 1, Stderr: "Error opening config file (X)"}) {
		t.Errorf("config EACCES 应识别(auditd 未启用常见形态)")
	}
	if isAuditLogUnavailable(nil) {
		t.Errorf("nil 不应识别")
	}
}

// --- helpers ---

// fakeExplainPipeline 装配 ausearch → audit2why → audit2allow 三段假执行:
// ausearch 把 record 喂回 onLine;audit2why 喂 whyOut;audit2allow --explain
// 喂 allowOut。
type fakeExplainPipeline struct {
	record   string
	whyOut   []string
	allowOut []string
}

func (p *fakeExplainPipeline) run(_ context.Context, bin string, _ io.Reader, onLine func([]byte) bool, _ ...string) error {
	if strings.Contains(bin, "ausearch") {
		return onLineLines(onLine, p.record)
	}
	if strings.Contains(bin, "audit2why") {
		for _, l := range p.whyOut {
			if !onLine([]byte(l)) {
				return nil
			}
		}
		return nil
	}
	for _, l := range p.allowOut {
		if !onLine([]byte(l)) {
			return nil
		}
	}
	return nil
}

func runFakeExplainPipeline(record string, whyOut, allowOut []string) *fakeExplainPipeline {
	return &fakeExplainPipeline{record: record, whyOut: whyOut, allowOut: allowOut}
}

func onLineLines(onLine func([]byte) bool, s string) error {
	for _, l := range strings.Split(s, "\n") {
		if !onLine([]byte(l)) {
			return nil
		}
	}
	return nil
}

func ptrStr(s string) *string { return &s }
func ptrInt(i int) *int       { return &i }
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json 序列化失败: %v", err)
	}
	return string(b)
}
