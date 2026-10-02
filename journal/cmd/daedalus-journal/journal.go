// journal 只读基元:直 fork journalctl 读取 journald 的结构化(JSON)输出,
// 把每行一个 JSON 对象还原为类型化 JournalEntry。
//
// 安全边界:参数在拼 argv 之前强制校验(unit 字符集 + 遍历检查、priority
// 0..7/名字枚举、since/until 字符集、grep 控制字符、limit 有界),再经
// exec.CommandContext 绝对路径 argv 直发,绝不经过 sh -c;since/until 用
// "--since=<val>" 等号形式,前导 '-' 不会被当作选项。缺 journalctl 一律优雅
// 降级为空集 + note,绝不 panic。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// journalctlBinary 是 journalctl 的绝对路径。包级变量而非常量的唯一理由:
// 测试注入 t.TempDir() 下的假脚本,永不触碰宿主真实 journald/journalctl。
var journalctlBinary = "/usr/bin/journalctl"

const (
	// journalctlTimeout 为单次 journalctl 调用的兜底超时;query/last_boot 直接
	// 受它约束,follow 在此之上再叠加更短的可注入上限。
	journalctlTimeout = 30 * time.Second

	// journalFollowTimeout 是 journal_follow 的墙钟上限;与条目上限二者先到
	// 即收工。定义为变量以便测试注入短值,不真等 30s。
	journalFollowTimeout = 30 * time.Second

	// journalFollowMaxEntries 是 journal_follow 单次返回的条目硬上限。
	journalFollowMaxEntries = 1000

	// journalDefaultLimit 是 journal_query 未显式给 limit 时的缺省条数。
	journalDefaultLimit = 100

	// journalMaxLimit 是 journal_query limit 的上界(超出即拒绝,防止拉爆内存)。
	journalMaxLimit = 1000

	// journalLastBootLimit 是 journal_last_boot 固定返回的最近条数。
	journalLastBootLimit = 50
)

// priorityNames 钉死 syslog PRIORITY 0..7 → 名字枚举;未知值查表得空串,
// 但保留条目本身(辅字段异常不丢整条消息)。
var priorityNames = map[string]string{
	"0": "emerg",
	"1": "alert",
	"2": "crit",
	"3": "err",
	"4": "warning",
	"5": "notice",
	"6": "info",
	"7": "debug",
}

// unitPattern 是单元名白名单正则:首字符必须是字母/数字/下划线(天然排除
// 前导 '-' 选项注入),其余允许字母/数字/下划线/点/@/-;'/'、空白、shell
// 元字符均被拒。".." 遍历由 Validate 单独兜底(字符类放行点号)。
var unitPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]*$`)

// timeFilterPattern 是 since/until 的字符集白名单:允许日期/时间字面量与
// 相对时长(-1h、today、2026-01-02 12:00:00)。分号、换行、反引号、重定向
// 等 shell 元字符一律在 argv 构造前被拒。
var timeFilterPattern = regexp.MustCompile(`^[A-Za-z0-9 :._+\-/@,]+$`)

// JournalEntry 是一条 journald 记录的类型化视图;仅暴露排障常用字段。
type JournalEntry struct {
	Timestamp        string `json:"timestamp"`
	Priority         string `json:"priority"`
	Unit             string `json:"unit,omitempty"`
	SyslogIdentifier string `json:"syslog_identifier,omitempty"`
	PID              string `json:"pid,omitempty"`
	Message          string `json:"message"`
}

// QueryResult 是 journal_query 的返回载荷;SkippedLines 记录被跳过的坏行数,
// Note 承载截断/降级等人类可读说明(无异常时为空)。
type QueryResult struct {
	Entries      []JournalEntry `json:"entries"`
	SkippedLines int            `json:"skipped_lines"`
	Note         string         `json:"note,omitempty"`
}

// FollowResult 是 journal_follow 的返回载荷(有界批量,非持久订阅)。
type FollowResult struct {
	Entries      []JournalEntry `json:"entries"`
	SkippedLines int            `json:"skipped_lines"`
	Note         string         `json:"note,omitempty"`
}

// LastBootResult 是 journal_last_boot 的返回载荷;journald 缺位时 Note 说明。
type LastBootResult struct {
	Entries []JournalEntry `json:"entries"`
	Note    string         `json:"note,omitempty"`
}

// QueryArgs 是 journal_query 的已校验入参;指针字段区分"未给"与"给空"。
type QueryArgs struct {
	Unit     *string
	Since    *string
	Until    *string
	Priority *string
	Grep     *string
	Limit    *int
}

// FollowArgs 是 journal_follow 的入参;Unit 必填,其余可选。
type FollowArgs struct {
	Unit     string
	Since    *string
	Until    *string
	Priority *string
	Grep     *string
}

// Validate 校验 journal_query 入参并补全 limit 缺省。一切拒绝都发生在拼
// argv 之前——非法输入永不抵达 exec。
func (a *QueryArgs) Validate() error {
	if a.Unit != nil {
		if *a.Unit == "" {
			return errors.New("unit 不能为空")
		}
		if !unitPattern.MatchString(*a.Unit) {
			return fmt.Errorf("非法 unit: %q", *a.Unit)
		}
		if strings.Contains(*a.Unit, "..") {
			return fmt.Errorf("非法 unit(路径遍历): %q", *a.Unit)
		}
	}
	if err := validateTimeFilter("since", a.Since); err != nil {
		return err
	}
	if err := validateTimeFilter("until", a.Until); err != nil {
		return err
	}
	if err := validatePriority(a.Priority); err != nil {
		return err
	}
	if err := validateGrep(a.Grep); err != nil {
		return err
	}
	if a.Limit == nil {
		def := journalDefaultLimit
		a.Limit = &def
	} else if *a.Limit < 1 || *a.Limit > journalMaxLimit {
		return fmt.Errorf("limit 必须在 1..%d 之间, got %d", journalMaxLimit, *a.Limit)
	}
	return nil
}

// Validate 校验 journal_follow 入参(unit 必填且字符集合法)。值接收器:
// 测试以非地址字面量直接调用,且本方法无需修改入参。
func (a FollowArgs) Validate() error {
	if a.Unit == "" {
		return errors.New("unit 不能为空")
	}
	if !unitPattern.MatchString(a.Unit) {
		return fmt.Errorf("非法 unit: %q", a.Unit)
	}
	if strings.Contains(a.Unit, "..") {
		return fmt.Errorf("非法 unit(路径遍历): %q", a.Unit)
	}
	if err := validateTimeFilter("since", a.Since); err != nil {
		return err
	}
	if err := validateTimeFilter("until", a.Until); err != nil {
		return err
	}
	if err := validatePriority(a.Priority); err != nil {
		return err
	}
	return validateGrep(a.Grep)
}

// validateTimeFilter 校验 since/until 字符集;空串视为未给过滤。
func validateTimeFilter(name string, v *string) error {
	if v == nil || *v == "" {
		return nil
	}
	if !timeFilterPattern.MatchString(*v) {
		return fmt.Errorf("非法 %s: %q", name, *v)
	}
	return nil
}

// validatePriority 接受 "0".."7" 或对应名字;其余一律拒绝。
func validatePriority(v *string) error {
	if v == nil || *v == "" {
		return nil
	}
	if _, ok := priorityNames[*v]; ok {
		return nil
	}
	for _, name := range priorityNames {
		if name == *v {
			return nil
		}
	}
	return fmt.Errorf("priority 非法: %q(应为 0..7 或 emerg..debug)", *v)
}

// validateGrep 拒绝控制字符(含 NUL、换行)与超长模式;空串视为未给过滤。
func validateGrep(v *string) error {
	if v == nil || *v == "" {
		return nil
	}
	s := *v
	if len(s) > 4096 {
		return fmt.Errorf("grep 过长(%d 字节)", len(s))
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return fmt.Errorf("grep 含控制字符")
		}
	}
	return nil
}

// execRunner 是外部 CLI 调用注入点:逐行喂给 onLine,onLine 返回 false 时
// 须中止子进程并正常收工。生产实现是 runJournalctl。
type execRunner func(ctx context.Context, onLine func([]byte) bool, args ...string) error

// service 持有 CLI 调用器与 follow 墙钟上限;测试以替身装配。
type service struct {
	run           execRunner
	followTimeout time.Duration
}

// newService 装配生产 service:真 fork journalctl,30s follow 上限。
func newService() *service {
	return &service{run: runJournalctl, followTimeout: journalFollowTimeout}
}

// Query 执行有界 journal_query:固定 -o json --no-pager -q + 过滤参数,收集
// 全部命中后若超出 limit 则保留尾部最近 limit 条并标注 note(fake/真 journalctl
// 忽略 -n 时的兜底)。缺 journalctl 降级为空集 + note。
func (s *service) Query(ctx context.Context, args QueryArgs) (QueryResult, error) {
	if err := args.Validate(); err != nil {
		return QueryResult{}, err
	}
	limit := *args.Limit

	argv := []string{"-o", "json", "--no-pager", "-q", "-n", strconv.Itoa(limit)}
	argv = appendFilterArgs(argv, args.Unit, args.Since, args.Until, args.Priority, args.Grep)

	var lines [][]byte
	err := s.run(ctx, func(line []byte) bool {
		lines = append(lines, append([]byte(nil), line...))
		return true
	}, argv...)
	if err != nil {
		if isMissingBinary(err) {
			return QueryResult{Note: "journalctl 不可用: " + err.Error()}, nil
		}
		return QueryResult{}, err
	}

	entries, skipped := parseEntries(lines)
	res := QueryResult{Entries: entries, SkippedLines: skipped}
	if len(entries) > limit {
		res.Entries = entries[len(entries)-limit:]
		res.Note = fmt.Sprintf("输出超过 limit=%d,已截断保留最近 %d 条", limit, limit)
	}
	return res, nil
}

// Follow 执行有界 journal_follow:--follow 直到墙钟上限或条目上限先到即收工,
// 返回已收集批量而非持久订阅。超时与条目上限都归为"上限"note,不返回 error。
func (s *service) Follow(ctx context.Context, args FollowArgs) (FollowResult, error) {
	if err := args.Validate(); err != nil {
		return FollowResult{}, err
	}
	execCtx, cancel := context.WithTimeout(ctx, s.followTimeout)
	defer cancel()

	argv := []string{"--follow", "-o", "json", "--no-pager", "-q"}
	argv = appendFilterArgs(argv, &args.Unit, args.Since, args.Until, args.Priority, args.Grep)

	entries := make([]JournalEntry, 0, journalFollowMaxEntries)
	skipped := 0
	err := s.run(execCtx, func(line []byte) bool {
		e, ok := parseEntry(line)
		if !ok {
			skipped++
			return true
		}
		entries = append(entries, e)
		return len(entries) < journalFollowMaxEntries
	}, argv...)

	res := FollowResult{Entries: entries, SkippedLines: skipped}
	switch {
	case err == nil || errors.Is(err, context.DeadlineExceeded):
		if len(entries) >= journalFollowMaxEntries || errors.Is(err, context.DeadlineExceeded) {
			res.Note = fmt.Sprintf("follow 达到条目或时间上限(%d 条 / %s),已返回批量", journalFollowMaxEntries, s.followTimeout)
		}
	case isMissingBinary(err):
		res.Entries = []JournalEntry{}
		res.Note = "journalctl 不可用: " + err.Error()
	default:
		// 父 ctx 取消属正常收工;其余错误上抛。
		if errors.Is(err, context.Canceled) {
			return res, nil
		}
		return FollowResult{}, err
	}
	return res, nil
}

// LastBoot 读取上一次启动(-b -1)的最近 journalLastBootLimit 条记录;无 error
// 返回,缺 journalctl 时降级为空集 + note。
func (s *service) LastBoot(ctx context.Context) LastBootResult {
	argv := []string{"-b", "-1", "-n", strconv.Itoa(journalLastBootLimit), "-o", "json", "--no-pager", "-q"}

	var lines [][]byte
	err := s.run(ctx, func(line []byte) bool {
		lines = append(lines, append([]byte(nil), line...))
		return true
	}, argv...)
	if err != nil {
		if isMissingBinary(err) {
			return LastBootResult{Entries: []JournalEntry{}, Note: "journalctl 不可用: " + err.Error()}
		}
		return LastBootResult{Entries: []JournalEntry{}, Note: "journalctl 调用失败: " + err.Error()}
	}

	entries, _ := parseEntries(lines)
	return LastBootResult{Entries: entries}
}

// appendFilterArgs 把可选过滤参数拼进 argv;unit 用 "-u <val>" 独立两参,
// since/until/priority/grep 一律用 "=" 等号形式,杜绝前导 '-' 被当选项。
func appendFilterArgs(argv []string, unit, since, until, priority, grep *string) []string {
	if unit != nil && *unit != "" {
		argv = append(argv, "-u", *unit)
	}
	if since != nil && *since != "" {
		argv = append(argv, "--since="+*since)
	}
	if until != nil && *until != "" {
		argv = append(argv, "--until="+*until)
	}
	if priority != nil && *priority != "" {
		argv = append(argv, "--priority="+*priority)
	}
	if grep != nil && *grep != "" {
		argv = append(argv, "--grep="+*grep)
	}
	return argv
}

// isMissingBinary 识别"journalctl 不在"的 ENOENT 降级信号。
func isMissingBinary(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, exec.ErrNotFound)
}

// runJournalctl 以绝对路径 argv 直发执行 journalctl(绝不经过 sh -c),逐行
// 把 stdout 回调给 onLine。cmd.Stdin 置空(→ /dev/null):服务器 stdin 是
// JSON-RPC 帧流,子进程继承会吞掉未读协议数据。onLine 返回 false 时杀子进程
// 并正常收工。静默退出码 1 + 空 stderr 是 journalctl "无匹配"语义,视为成功。
func runJournalctl(ctx context.Context, onLine func([]byte) bool, args ...string) error {
	execCtx, cancel := context.WithTimeout(ctx, journalctlTimeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, journalctlBinary, args...)
	cmd.Stdin = nil
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("journalctl stdout 管道失败: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("journalctl 启动失败: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	// 单条 JSON 记录可能很长(完整 MESSAGE/二进制字段),把行缓冲上限抬到 16MiB。
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		if !onLine(scanner.Bytes()) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil
		}
	}
	scanErr := scanner.Err()
	waitErr := cmd.Wait()

	if scanErr != nil {
		return fmt.Errorf("journalctl 读取失败: %w", scanErr)
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) && stderr.Len() == 0 {
			// 无匹配时 journalctl 以退出码 1 + 空 stderr 表示,不是故障。
			return nil
		}
		return fmt.Errorf("journalctl 失败: %w(%s)", waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// parseEntries 逐行解析,返回好条目与坏行计数;坏行跳过,整体不崩。
func parseEntries(lines [][]byte) ([]JournalEntry, int) {
	entries := make([]JournalEntry, 0, len(lines))
	skipped := 0
	for _, line := range lines {
		e, ok := parseEntry(line)
		if !ok {
			skipped++
			continue
		}
		entries = append(entries, e)
	}
	return entries, skipped
}

// parseEntry 解析一行 journalctl -o json 对象;缺 __REALTIME_TIMESTAMP 或非
// JSON 返回 ok=false,PRIORITY 等辅字段异常只留空、不丢条目。
func parseEntry(line []byte) (JournalEntry, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return JournalEntry{}, false
	}
	tsRaw, ok := raw["__REALTIME_TIMESTAMP"]
	if !ok {
		return JournalEntry{}, false
	}
	us, err := strconv.ParseInt(rawToString(tsRaw), 10, 64)
	if err != nil {
		return JournalEntry{}, false
	}
	return JournalEntry{
		Timestamp:        time.Unix(0, us*1000).UTC().Format(time.RFC3339Nano),
		Priority:         priorityNames[rawToString(raw["PRIORITY"])],
		Unit:             rawToString(raw["_SYSTEMD_UNIT"]),
		SyslogIdentifier: rawToString(raw["SYSLOG_IDENTIFIER"]),
		PID:              rawToString(raw["_PID"]),
		Message:          rawToString(raw["MESSAGE"]),
	}, true
}

// rawToString 把 JSON 标量还原为字符串:字符串去引号,数字/布尔取字面量,
// MESSAGE 的字节数组形态(非 UTF-8)按字节还原。
func rawToString(r json.RawMessage) string {
	if len(r) == 0 {
		return ""
	}
	trimmed := bytes.TrimSpace(r)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []int
		if err := json.Unmarshal(trimmed, &arr); err == nil {
			b := make([]byte, len(arr))
			for i, v := range arr {
				b[i] = byte(v)
			}
			return string(b)
		}
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		return s
	}
	return strings.Trim(string(trimmed), `"`)
}
