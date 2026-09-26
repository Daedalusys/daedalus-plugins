// audit.jsonl 只读回放扫描:路径解析(env → 系统 → $HOME)、逐行流式解析
// (audit.ParseValue)、过滤(session/tool/tx/时间界)与行号游标分页。
// 视图层对损坏行**宽容跳过**(完整性校验是 audit.Verify 的职责,视图不抢);
// 本文件零写入、零 exec。
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Daedalusys/daedalus-sdk/audit"
)

// 审计日志路径解析链常量:env 覆盖复用 SDK 的 audit.EnvLogPath;
// 系统路径与 SDK 的私有默认值逐字同源(SDK 未导出常量,只导出 DefaultLogPath)。
const (
	systemAuditLogPath = "/var/log/daedalus/audit.jsonl"
	homeAuditLogRel    = ".local/share/daedalus/audit.jsonl"
)

// ErrNoUsableAuditLog 表示 env/系统/$HOME 三候选没有一个可读——显式报错,
// 绝不回落到不存在的路径上静默返回空视图。
var ErrNoUsableAuditLog = errors.New("trace: 无可读审计日志(env/系统/$HOME 均不可用)")

// resolveAuditLog 解析只读视图的数据源:
//  1. DAEDALUS_AUDIT_LOG_PATH 存在 → 直接采用(与 SDK DefaultLogPath 同语义),
//     但必须可读,不可读即报错(误配置不静默降级);
//  2. 系统路径 /var/log/daedalus/audit.jsonl 可读 → 采用;
//  3. $HOME/.local/share/daedalus/audit.jsonl 可读 → 采用(用户态 fallback);
//  4. 全部不可用 → ErrNoUsableAuditLog。
func resolveAuditLog() (string, error) {
	if v := os.Getenv(audit.EnvLogPath); v != "" {
		if usableAuditLog(v) {
			return v, nil
		}
		return "", fmt.Errorf("trace: 环境变量 %s 指向的日志不可读: %s", audit.EnvLogPath, v)
	}
	candidates := []string{systemAuditLogPath}
	if home := os.Getenv("HOME"); home != "" {
		candidates = append(candidates, home+"/"+homeAuditLogRel)
	}
	for _, c := range candidates {
		if usableAuditLog(c) {
			return c, nil
		}
	}
	return "", fmt.Errorf("%w(候选: %v)", ErrNoUsableAuditLog, candidates)
}

// usableAuditLog 可读性探测:只 open/close,绝不创建或截断文件。
func usableAuditLog(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	return f.Close() == nil
}

// traceEntry 是时间线里的一条可读回放条目。字段与磁盘记录一一对应;
// Args 取哈希载荷同源的规范化文本(ArgsString),视图只展示不改写。
type traceEntry struct {
	LineNo     int64  `json:"line_no"`
	Timestamp  string `json:"timestamp"`
	Identity   string `json:"identity"`
	Tool       string `json:"tool"`
	Outcome    string `json:"outcome"`
	Args       string `json:"args"`
	TxID       string `json:"tx_id,omitempty"`
	TxStep     *int64 `json:"tx_step,omitempty"`
	TxPrevHash string `json:"tx_prev_hash,omitempty"`
	EntryHash  string `json:"entry_hash"`
}

// viewFilter 汇总四个工具的过滤维度;零值字段 = 不限制。
// Since/Until 用 time.Time 零值语义(未提供不裁剪)。
type viewFilter struct {
	sessionID string
	toolName  string
	txID      string
	since     time.Time
	until     time.Time
}

// scanOutcome 是一次扫描的完整结果:命中条目 + 续传游标 + 统计计数。
type scanOutcome struct {
	Entries       []traceEntry `json:"entries"`
	NextCursor    int64        `json:"next_cursor"` // 0 = 已扫尽;>0 = 以 cursor=该值续传
	ScannedLines  int64        `json:"scanned_lines"`
	MatchedTotal  int64        `json:"matched_total"` // 含被 limit 截断的命中,不含游标跳过行
	MalformedSkip int64        `json:"malformed_skipped"`
}

// maxLineBytes 与 audit.Verify 同参:审计行可能携带长 args,单行上限 4MiB。
const maxLineBytes = 4 * 1024 * 1024

// scanAuditLog 流式扫描 logPath:cursor 之前的行直接跳过(不解析);
// 命中 filter 且未达 limit 的行进入 Entries,limit 满后仅继续计数不收集
// (MatchedTotal 保持真实,NextCursor 由截断点决定)。
// 空行与不可解析/非对象/缺必填字符串字段的行计入 MalformedSkip 并跳过。
func scanAuditLog(logPath string, cursor int64, f viewFilter, limit int) (*scanOutcome, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("trace: 打开审计日志失败: %w", err)
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	out := &scanOutcome{Entries: []traceEntry{}}
	truncated := false
	for lineNo := int64(1); sc.Scan(); lineNo++ {
		out.ScannedLines = lineNo
		if lineNo <= cursor {
			continue
		}
		entry, ok := parseTraceEntry(strings.TrimSpace(sc.Text()), lineNo)
		if !ok {
			out.MalformedSkip++
			continue
		}
		if !entryMatches(entry, f) {
			continue
		}
		out.MatchedTotal++
		if len(out.Entries) < limit {
			out.Entries = append(out.Entries, entry)
		} else {
			truncated = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("trace: 读取审计日志失败: %w", err)
	}
	if truncated {
		out.NextCursor = out.Entries[len(out.Entries)-1].LineNo
	}
	return out, nil
}

// parseTraceEntry 把一行 JSON 还原为视图条目;缺任一必填字符串字段
// (timestamp/identity/tool/outcome/prev_hash/entry_hash)或 args 键缺失
// 都判为不可回放行(ok=false)。tx_step 缺失/非数字按非 tx 行容忍。
func parseTraceEntry(line string, lineNo int64) (traceEntry, bool) {
	if line == "" {
		return traceEntry{}, false
	}
	v, err := audit.ParseValue(line)
	if err != nil || !v.IsObject() {
		return traceEntry{}, false
	}
	e := traceEntry{LineNo: lineNo}
	for _, spec := range []struct {
		key string
		dst *string
	}{
		{"timestamp", &e.Timestamp}, {"identity", &e.Identity}, {"tool", &e.Tool},
		{"outcome", &e.Outcome}, {"entry_hash", &e.EntryHash},
	} {
		s, ok := v.LookupString(spec.key)
		if !ok {
			return traceEntry{}, false
		}
		*spec.dst = s
	}
	args, ok := v.Lookup("args")
	if !ok {
		return traceEntry{}, false
	}
	e.Args = args.ArgsString()
	// prev_hash 是合法记录的必备键(与 Verify 的 requiredFields 同判据),
	// 但视图不重算哈希,取到即弃,只保留"缺键=损坏"这一否决作用。
	if _, ok := v.LookupString("prev_hash"); !ok {
		return traceEntry{}, false
	}
	e.TxID, _ = v.LookupString("tx_id")
	if e.TxID != "" {
		txPrev, _ := v.LookupString("tx_prev_hash")
		e.TxPrevHash = txPrev
		if step, ok := v.Lookup("tx_step"); ok && step != nil {
			if n, err := parseIntValue(step); err == nil {
				e.TxStep = &n
			}
		}
	}
	return e, true
}

// parseIntValue 读取 audit.Value 的整数形态:Value 不导出 kind,
// 规范化十进制文本经 ArgsString 取得后 strconv 还原(非整数文本即报错)。
func parseIntValue(v *audit.Value) (int64, error) {
	return strconv.ParseInt(v.ArgsString(), 10, 64)
}

// entryMatches 判定条目是否落入当前过滤视图。时间界比较用记录自身
// 文本解析出的 RFC3339 时刻;时间戳不可解析的行在任何时间界过滤下
// fail-closed 排除(无法定位区间的条目不冒充区间内数据)。
func entryMatches(e traceEntry, f viewFilter) bool {
	if f.sessionID != "" && e.Identity != f.sessionID {
		return false
	}
	if f.toolName != "" && e.Tool != f.toolName {
		return false
	}
	if f.txID != "" && e.TxID != f.txID {
		return false
	}
	if !f.since.IsZero() || !f.until.IsZero() {
		ts, err := time.Parse(time.RFC3339, e.Timestamp)
		if err != nil {
			return false
		}
		if !f.since.IsZero() && ts.Before(f.since) {
			return false
		}
		if !f.until.IsZero() && ts.After(f.until) {
			return false
		}
	}
	return true
}

// parseTimeBound 解析 since/until 入参(RFC3339,Z 或 ±偏移均可)。
func parseTimeBound(name, value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("trace: %s 不是合法 RFC3339 时间: %q", name, value)
	}
	return t.UTC(), nil
}

// validateViewID 校验会话/工具/事务过滤标识。过滤值只做字符串等值比较、
// 永不进入 exec 或路径,故不设字符类白名单;底线为非空、长度上限与
// 控制字符拒绝(避免把换行/退格之类噪声带进回包与统计)。
func validateViewID(kind, id string) error {
	if id == "" {
		return fmt.Errorf("trace: %s 不能为空", kind)
	}
	if len(id) > 128 {
		return fmt.Errorf("trace: %s 超长(>128): %q", kind, id)
	}
	if strings.ContainsAny(id, "\x00\n\r") {
		return fmt.Errorf("trace: %s 含控制字符: %q", kind, id)
	}
	return nil
}
