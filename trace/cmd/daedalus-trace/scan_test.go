// trace 扫描层单元测试:路径解析链、行解析、游标分页、时间界与校验纯函数。
// 夹具双轨——哈希链真实行经 audit.LogAudit 生成(与发射端同源),
// 手写行只走视图解析路径(视图不重算哈希,时间戳可钉死)。
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Daedalusys/daedalus-sdk/audit"
)

// appendLine 以 Python json.dumps 磁盘形态手工追加一行(仅视图解析,
// 不要求哈希链自洽——完整性是 audit.Verify 的职责)。
func appendAuditLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("追加夹具行失败: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatalf("写入夹具行失败: %v", err)
	}
}

// handLine 生成指定 identity/tool/outcome/timestamp 的合法记录行。
func handLine(identity, tool, outcome, timestamp string) string {
	return `{"args": {}, "entry_hash": "e-` + identity + `", "identity": "` + identity +
		`", "outcome": "` + outcome + `", "policy_version": "1.0", "prev_hash": "p",` +
		` "timestamp": "` + timestamp + `", "tool": "` + tool + `"}`
}

func TestResolveAuditLog_EnvAndHome(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if _, err := audit.LogAudit(audit.Entry{Identity: "cli", Tool: "t", LogPath: path}); err != nil {
		t.Fatalf("夹具日志生成失败: %v", err)
	}

	t.Setenv(audit.EnvLogPath, path)
	if got, err := resolveAuditLog(); err != nil || got != path {
		t.Fatalf("env 覆盖解析 = (%q, %v), want %q", got, err, path)
	}

	t.Setenv(audit.EnvLogPath, filepath.Join(dir, "missing.jsonl"))
	if _, err := resolveAuditLog(); err == nil {
		t.Fatal("env 指向不可读路径必须报错(fail-closed,不静默降级)")
	}

	// 无 env:系统路径若在本机存在则跳过 home 兜底断言(视图工具无法
	// 操纵宿主 /var/log;CI 干净环境必走兜底分支)。
	t.Setenv(audit.EnvLogPath, "")
	if usableAuditLog(systemAuditLogPath) {
		t.Skip("宿主存在系统审计日志,home 兜底分支不可测")
	}
	home := t.TempDir()
	homeLog := filepath.Join(home, ".local", "share", "daedalus", "audit.jsonl")
	if err := os.MkdirAll(filepath.Dir(homeLog), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.LogAudit(audit.Entry{Identity: "cli", Tool: "t", LogPath: homeLog}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	if got, err := resolveAuditLog(); err != nil || got != homeLog {
		t.Fatalf("home 兜底解析 = (%q, %v), want %q", got, err, homeLog)
	}
}

func TestResolveAuditLog_NoUsable(t *testing.T) {
	t.Setenv(audit.EnvLogPath, "")
	if usableAuditLog(systemAuditLogPath) {
		t.Skip("宿主存在系统审计日志")
	}
	t.Setenv("HOME", t.TempDir()) // 空 home,无兜底文件
	if _, err := resolveAuditLog(); err == nil {
		t.Fatal("全部候选不可读必须显式报错,绝不回落静默路径")
	}
}

func TestParseTraceEntry_ValidAndMalformed(t *testing.T) {
	rec, err := audit.LogAudit(audit.Entry{
		Identity: "cli", Tool: "fs.read_file", LogPath: filepath.Join(t.TempDir(), "a.jsonl"),
		Args: audit.NewObject(), TxID: "tx-7", TxStep: 2, TxPrevHash: "abcd",
	})
	if err != nil {
		t.Fatalf("LogAudit 失败: %v", err)
	}
	e, ok := parseTraceEntry(rec.Line(), 42)
	if !ok {
		t.Fatalf("真实记录行被判损坏: %s", rec.Line())
	}
	if e.LineNo != 42 || e.Identity != "cli" || e.Tool != "fs.read_file" ||
		e.TxID != "tx-7" || e.TxStep == nil || *e.TxStep != 2 || e.TxPrevHash != "abcd" ||
		e.EntryHash != rec.EntryHash || e.Args != "{}" {
		t.Errorf("字段还原漂移: %+v", e)
	}

	for _, bad := range []string{
		"", "0 tokens processed.", "[]", `"plain string"`,
		`{"identity":"cli"}`, // 缺必填字符串
		`{"timestamp":"t","identity":"c","tool":"t","outcome":"s","prev_hash":"p","entry_hash":"e"}`, // 缺 args
	} {
		if _, ok := parseTraceEntry(bad, 1); ok {
			t.Errorf("损坏行被接受: %s", bad)
		}
	}
}

func TestScanAuditLog_CursorPagination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for i := 0; i < 5; i++ {
		appendAuditLine(t, path, handLine("cli", "t", "success", "2026-01-01T00:00:0"+string(rune('0'+i))+"+00:00"))
	}
	out, err := scanAuditLog(path, 0, viewFilter{}, 2)
	if err != nil {
		t.Fatalf("首扫失败: %v", err)
	}
	if len(out.Entries) != 2 || out.NextCursor != 2 || out.MatchedTotal != 5 {
		t.Fatalf("首扫 = (%d 条, cursor %d, total %d), want (2, 2, 5)",
			len(out.Entries), out.NextCursor, out.MatchedTotal)
	}
	out2, err := scanAuditLog(path, out.NextCursor, viewFilter{}, 2)
	if err != nil {
		t.Fatalf("续扫失败: %v", err)
	}
	if len(out2.Entries) != 2 || out2.NextCursor != 4 || out2.Entries[0].LineNo != 3 {
		t.Fatalf("续扫 = (%d 条, cursor %d, 首行 %d), want (2, 4, 3)",
			len(out2.Entries), out2.NextCursor, out2.Entries[0].LineNo)
	}
	out3, err := scanAuditLog(path, out2.NextCursor, viewFilter{}, 2)
	if err != nil {
		t.Fatalf("尾扫失败: %v", err)
	}
	if len(out3.Entries) != 1 || out3.NextCursor != 0 {
		t.Fatalf("尾扫 = (%d 条, cursor %d), want (1, 0 扫尽)", len(out3.Entries), out3.NextCursor)
	}
}

func TestScanAuditLog_FiltersAndMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	appendAuditLine(t, path, handLine("cli", "fs.read_file", "success", "2026-01-01T10:00:00+00:00"))
	appendAuditLine(t, path, "garbage line")
	appendAuditLine(t, path, handLine("daedalus-copilot", "shell_exec", "denied", "2026-02-01T10:00:00+00:00"))
	appendAuditLine(t, path, handLine("daedalus-copilot", "shell_exec", "success", "2026-03-01T10:00:00+00:00"))

	out, err := scanAuditLog(path, 0, viewFilter{sessionID: "daedalus-copilot"}, maxLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 2 || out.MalformedSkip != 1 || out.ScannedLines != 4 {
		t.Fatalf("session 过滤 = %v(malformed %d, lines %d)", out.Entries, out.MalformedSkip, out.ScannedLines)
	}
	// 时间界:[2026-01-15, 2026-02-15) 只含 denied 行;坏时间戳行在时间界下 fail-closed。
	since, _ := parseTimeBound("since", "2026-01-15T00:00:00Z")
	until, _ := parseTimeBound("until", "2026-02-15T00:00:00Z")
	out, err = scanAuditLog(path, 0, viewFilter{toolName: "shell_exec", since: since, until: until}, maxLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 || out.Entries[0].Outcome != "denied" {
		t.Fatalf("时间界过滤 = %+v, want 仅 denied 行", out.Entries)
	}
	if _, err := scanAuditLog(filepath.Join(t.TempDir(), "none.jsonl"), 0, viewFilter{}, 10); err == nil {
		t.Fatal("日志文件缺失必须报错")
	}
}

func TestValidateViewIDAndTimeBound(t *testing.T) {
	for _, bad := range []string{"", strings.Repeat("x", 129), "a\nb", "a\x00b", "a\rb"} {
		if err := validateViewID("session_id", bad); err == nil {
			t.Errorf("非法标识被放行: %q", bad)
		}
	}
	if err := validateViewID("session_id", "daedalus-copilot"); err != nil {
		t.Errorf("合法标识被误拒: %v", err)
	}
	if _, err := parseTimeBound("since", "2026-01-01 00:00:00"); err == nil {
		t.Error("非 RFC3339 时间界必须拒绝")
	}
	tt, err := parseTimeBound("since", "2026-01-01T00:00:00+08:00")
	if err != nil || !tt.Equal(time.Date(2025, 12, 31, 16, 0, 0, 0, time.UTC)) {
		t.Errorf("+08:00 偏移归一 = (%v, %v), want UTC 2025-12-31T16:00", tt, err)
	}
}
