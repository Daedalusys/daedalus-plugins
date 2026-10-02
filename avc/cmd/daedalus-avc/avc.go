// Command daedalus-avc 是 SELinux AVC 拒绝记录只读 MCP 服务器(stdio JSON-RPC)。
//
// 提供 3 个 L0 工具:avc_recent(ausearch -m avc,user_avc 列表)、avc_explain
// (ausearch -a <id> + audit2why + audit2allow --explain 单事件解释)、
// avc_summary(按 scontext|tclass|comm|perm 聚合的频次统计)。全部直 fork 三只
// CLI(ausearch / audit2why / audit2allow),零写入;任意 CLI 缺失一律优雅降级为
// 空集 + note,绝不修改 SELinux 策略。
//
// 安全边界:入参在拼 argv 前强制校验,绝对路径 argv 直发不走 sh -c;工具名与
// manifest.tools 逐字一致(76 脚本构建期交叉核对,漂移即构建失败)。审计日志
// 为 0600 root:root,部署态经 AmbientCapabilities=CAP_DAC_READ_SEARCH 换取读
// 权限(见 Daedalusys/.../daedalus-avc.service)。
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// --- 二进制路径 / 超时 / 边界 ---

// 三只 CLI 的绝对路径常量。ausearch 在 /usr/sbin,audit2why/audit2allow 在
// /usr/bin(实际由 policycoreutils-python 包提供;audit2why 是 audit2allow
// 的符号链接,接受 -w 等同 --explain)。
//
// 实机路径与 pre-ruling 中假定的 /usr/sbin/audit2why 有别:本仓以实机 + 真实可
// exec 路径为准,manifest.run 列表同步登记。测试可改写以指向临时脚本。
var (
	ausearchBinary    = "/usr/sbin/ausearch"
	audit2whyBinary   = "/usr/bin/audit2why"
	audit2allowBinary = "/usr/bin/audit2allow"
)

// 上限 / 超时:与 journal/integrity 收敛一致。
const (
	avcDefaultLimit = 200
	avcMaxLimit     = 10000
	avcTimeout      = 30 * time.Second
)

// --- 入参校验 ---

// sincePattern 限定合法 since 形态(ausearch -ts 的词法字符串子集),杜绝注入
// 与遍历。ausearch -ts 接受关键字(today/yesterday/now/recent/this-week/
// this-month/this-year/monday..sunday)或日期(MM/DD/YYYY[ HH:MM:SS] /
// YYYY-MM-DD[ HH:MM:SS])。首字符必须字母数字 (允许),
// 含空格字符 (拒绝),严格 --since=<val> 等号拼合后第一个字符
// 一定不是 '-'。
//
// 实测 ausearch -ts 也接 today/yesterday/now/recent;this-week 等是 RHEL 4+
// 文档承诺,实际不验证不影响。
var sincePattern = regexp.MustCompile(`^(today|yesterday|now|recent|this-week|this-month|this-year|monday|tuesday|wednesday|thursday|friday|saturday|sunday|\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?|\d{1,2}/\d{1,2}/\d{4}( \d{1,2}:\d{2}(:\d{2})?)?)$`)

// eventIDPattern 限定 audit event id 形态(ausearch -a 的合法形式)。实机
// ausearch -a 只接纯数字序列号(如 "42");为了与 msg=audit(...) 的"epoch:serial"
// 形态兼容(测试夹具中常见),允许冒号分隔的两段。
var eventIDPattern = regexp.MustCompile(`^[0-9]+(:[0-9]+)?$`)

// RecentArgs 是 avc_recent 的已校验入参:since 可选(ausearch -ts 字符串);
// limit 缺省 avcDefaultLimit,最大 avcMaxLimit。
type RecentArgs struct {
	Since *string
	Limit *int
}

// Validate 校验 avc_recent 入参并补全 limit 缺省。先 since 字符串合法,再
// limit 边界。offset 在 avc_recent 形态下不暴露——服务侧全量收行后按 limit
// 截断,off=0 即足。
func (a *RecentArgs) Validate() error {
	if a.Since != nil && *a.Since != "" {
		if strings.ContainsAny(*a.Since, "\t\n") || strings.HasPrefix(*a.Since, "-") || strings.ContainsAny(*a.Since, "$`|;&") {
			return fmt.Errorf("非法 since: %q", *a.Since)
		}
		if !sincePattern.MatchString(*a.Since) {
			return fmt.Errorf("非法 since 形态: %q", *a.Since)
		}
	}
	if a.Limit == nil {
		dflt := avcDefaultLimit
		a.Limit = &dflt
	} else if *a.Limit < 1 || *a.Limit > avcMaxLimit {
		return fmt.Errorf("limit 必须在 1..%d 之间, got %d", avcMaxLimit, *a.Limit)
	}
	return nil
}

// ExplainArgs 是 avc_explain 的入参(仅 event_id,since 不接)。
type ExplainArgs struct {
	EventID string
}

// Validate 校验 event_id 形态:仅数字或 "epoch:serial"。拒绝注入与遍历。
func (a *ExplainArgs) Validate() error {
	if a.EventID == "" {
		return fmt.Errorf("event_id 不能为空")
	}
	if !eventIDPattern.MatchString(a.EventID) {
		return fmt.Errorf("非法 event_id 形态: %q", a.EventID)
	}
	return nil
}

// SummaryArgs 是 avc_summary 的入参:since 可选,limit 不接(返回桶集合,而非
// 事件流)。
type SummaryArgs struct {
	Since *string
}

// Validate 校验 since 形态(同 RecentArgs)。
func (a *SummaryArgs) Validate() error {
	if a.Since != nil && *a.Since != "" {
		if strings.ContainsAny(*a.Since, "\t\n") || strings.HasPrefix(*a.Since, "-") || strings.ContainsAny(*a.Since, "$`|;&") {
			return fmt.Errorf("非法 since: %q", *a.Since)
		}
		if !sincePattern.MatchString(*a.Since) {
			return fmt.Errorf("非法 since 形态: %q", *a.Since)
		}
	}
	return nil
}

// --- 载荷类型 ---

// AVCEvent 是单条 AVC 拒绝记录的类型化视图,字段名对应 daley::policy.toml
// avc 子对象的 wire 形态。
type AVCEvent struct {
	EventID    string `json:"event_id"`
	Type       string `json:"type"`                // AVC | USER_AVC
	SContext   string `json:"scontext"`            // 源域
	TContext   string `json:"tcontext"`            // 目标域
	TClass     string `json:"tclass"`              // 目标类(file / dir / tcp_socket 等)
	Perm       string `json:"perm"`                // 被拒权限
	Comm       string `json:"comm,omitempty"`      // 命令名
	PID        string `json:"pid,omitempty"`       // pid
	Permissive bool   `json:"permissive"`          // permissive=1 时为 true
	Timestamp  string `json:"timestamp,omitempty"` // msg=audit(...) 的 epoch 部分
}

// RecentResult 是 avc_recent 的返回载荷:Events 是解析结果数组(空切片保证 wire
// 是 "[]" 不是 "null"),TotalLines 是 ausearch stdout 收行数,Returned 是本次
// 实际返回条数,Truncated 表示被分页截断,Note 承载截断/降级等人类可读说明。
type RecentResult struct {
	Events     []AVCEvent `json:"events"`
	TotalLines int        `json:"total_lines"`
	Returned   int        `json:"returned"`
	Truncated  bool       `json:"truncated"`
	Note       string     `json:"note,omitempty"`
}

// SummaryBucket 是单条聚合桶:Key 是 "scontext|tclass|comm|perm" 串,Count 是
// 出现次数。
type SummaryBucket struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// SummaryResult 是 avc_summary 的返回载荷:Total 是事件总数,Buckets 是按 Count
// 降序排列的桶集合,Note 承载降级等人类可读说明。
type SummaryResult struct {
	Total   int             `json:"total"`
	Buckets []SummaryBucket `json:"buckets"`
	Note    string          `json:"note,omitempty"`
}

// Explanation 是 avc_explain 的返回载荷:Reason 是 audit2why 解释的纯文本
// (去标签),Suggestion 是 audit2allow --explain 的建议策略(去注释 + 保留核心
// allow 规则行),Confidence 是预留分类(empty / "type_enforcement" /
// "boolean" 等),Note 承载 audit2why/audit2allow 缺失或无匹配等降级信息。
type Explanation struct {
	EventID    string `json:"event_id"`
	Reason     string `json:"reason,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Note       string `json:"note,omitempty"`
}

// --- 解析器 ---

// avcLineRegex 匹配 ausearch --format default 的 "type=AVC msg=audit(...): ..."
// 单行。捕获组:type, msg=audit(TS:ID) → ts, id;denied { perm } → perm;
// pid= → pid;comm=" → quoted;name=" → name;scontext= → scontext;
// tcontext= → tcontext;tclass= → tclass;permissive= → permissive。
//
// 已知 perm = utf8(中英文都允许,因为 comm 可被翻译)、name 可能为空。
var avcLineRegex = regexp.MustCompile(`type=(AVC|USER_AVC) msg=audit\(([^)]+)\):\s+avc:\s+denied\s+\{ ([^}]+) \}\s+for\s+(?:pid=([0-9]+)\s+)?comm="([^"]*)"(?:\s+name="([^"]*)")?(?:\s+dev="[^"]*")?(?:\s+ino=[0-9]+)?(?:\s+path="[^"]*")?\s+scontext=(\S+)\s+tcontext=(\S+)\s+tclass=(\S+)(?:\s+permissive=([01]))?`)

// parseAvcEvents 解析 ausearch --format default 的逐行输出,返回成功匹配
// 的 AVCEvent 切片。空输出 / <no matches> / 坏行不报错。
func parseAvcEvents(lines [][]byte) []AVCEvent {
	out := make([]AVCEvent, 0)
	for _, line := range lines {
		s := strings.TrimSpace(string(line))
		if s == "" || s == "<no matches>" || strings.HasPrefix(s, "----") || strings.HasPrefix(s, "time->") {
			continue
		}
		m := avcLineRegex.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		ev := AVCEvent{
			Type:     m[1],
			Perm:     strings.TrimSpace(m[3]),
			SContext: m[7],
			TContext: m[8],
			TClass:   m[9],
		}
		// msg=audit(epoch.serial:id) → epoch 与 id 分别取出
		auditInner := m[2] // "1699287200.123:42"
		parts := strings.SplitN(auditInner, ":", 2)
		if len(parts) == 2 {
			ev.Timestamp = parts[0]
			ev.EventID = parts[1]
		} else {
			ev.EventID = parts[0]
		}
		if m[4] != "" {
			ev.PID = m[4]
		}
		if m[5] != "" {
			ev.Comm = m[5]
		}
		if m[10] == "1" {
			ev.Permissive = true
		}
		out = append(out, ev)
	}
	return out
}

// --- service / runner ---

// execRunner 是外部 CLI 调用的注入点:逐行把 stdout 喂给 onLine,onLine 返回
// false 时须中止子进程并正常收工。生产实现是 runCLI。
type execRunner func(ctx context.Context, bin string, onLine func([]byte) bool, args ...string) error

// stdinExecRunner 是带 stdin 的外部 CLI 调用注入点(用于 audit2why /
// audit2allow < <event_record>)。生产实现是 stdinRunner。
type stdinExecRunner func(ctx context.Context, bin string, stdin []byte, onLine func([]byte) bool, args ...string) error

// service 持有 CLI 调用器与调用方超时;测试以替身装配。
type service struct {
	run      execRunner
	runStdin stdinExecRunner
	timeout  time.Duration
}

// newService 装配生产 service:真 fork 三只 CLI,30s 超时上限。
func newService() *service {
	return &service{run: runCLI, runStdin: stdinRunner, timeout: avcTimeout}
}

// Recent 执行 avc_recent:ausearch -m avc,user_avc --format default [+可选]
// + 解析 + 截断。合法空结果(无匹配)→ 0 条 + note;binary 缺失 → 0 条 + note;
// rc≥2 → 真错误上抛。
func (s *service) Recent(ctx context.Context, args RecentArgs) (RecentResult, error) {
	if err := args.Validate(); err != nil {
		return RecentResult{}, err
	}
	execCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	argv := []string{"-m", "avc,user_avc", "--format", "default"}
	if args.Since != nil && *args.Since != "" {
		// 等号形式拼合,杜绝前导 '-' 被当选项。
		argv = append(argv, "-ts", *args.Since)
	}

	var lines [][]byte
	execNote := ""
	err := s.run(execCtx, ausearchBinary, func(line []byte) bool {
		lines = append(lines, append([]byte(nil), line...))
		return true
	}, argv...)
	if err != nil {
		note, fatal := handleExecError(err)
		if fatal {
			return RecentResult{}, err
		}
		execNote = note
	}

	events := parseAvcEvents(lines)
	page := visibleEvents(events, *args.Limit)
	if execNote != "" {
		page.Note = mergeNotes(execNote, page.Note)
	}
	return page, nil
}

// visibleEvents 按 limit 切片并填充分页统计(offset 在 avc_recent 形态下为 0)。
func visibleEvents(in []AVCEvent, limit int) RecentResult {
	res := RecentResult{
		Events:     []AVCEvent{},
		TotalLines: len(in),
	}
	for _, ev := range in {
		if res.Returned >= limit {
			res.Truncated = true
			continue
		}
		res.Events = append(res.Events, ev)
		res.Returned++
	}
	if res.Truncated {
		res.Note = fmt.Sprintf("输出超过 limit=%d,已截断", limit)
	}
	return res
}

// Explain 执行 avc_explain:三段管线——ausearch 拉原记录 → audit2why 解释
// 原因 → audit2allow --explain 给建议规则。任何一段降级均不阻断其他段。
func (s *service) Explain(ctx context.Context, args ExplainArgs) (Explanation, error) {
	if err := args.Validate(); err != nil {
		return Explanation{}, err
	}
	execCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	res := Explanation{EventID: args.EventID}

	// 第 1 段:拉原记录
	var record bytes.Buffer
	var lines [][]byte
	err := s.run(execCtx, ausearchBinary, func(line []byte) bool {
		lines = append(lines, append([]byte(nil), line...))
		record.Write(line)
		record.WriteByte('\n')
		return true
	}, "-a", args.EventID, "-m", "avc,user_avc", "--format", "default")
	if err != nil {
		note, fatal := handleExecError(err)
		if fatal {
			return Explanation{}, err
		}
		if isMissingBinary(err) {
			return Explanation{EventID: args.EventID, Note: "ausearch 不可用: " + err.Error()}, nil
		}
		// <no matches> / 审计日志不可读 → 优雅 note
		if record.Len() == 0 {
			return Explanation{EventID: args.EventID, Note: note}, nil
		}
	}
	// 兼容:ausearch rc=0 + 0 行也视为无匹配(不应在实机发生,但兜底)
	if record.Len() == 0 && err == nil {
		return Explanation{EventID: args.EventID, Note: "该 event_id 未匹配到 AVC/USER_AVC 事件"}, nil
	}

	// 第 2 段:audit2why 解释
	var whyBuf bytes.Buffer
	whyErr := s.runStdin(execCtx, audit2whyBinary, record.Bytes(), func(line []byte) bool {
		whyBuf.Write(line)
		whyBuf.WriteByte('\n')
		return true
	})
	if whyErr != nil {
		_, fatal := handleExecError(whyErr)
		if fatal {
			return Explanation{EventID: args.EventID, Note: "audit2why 调用失败: " + whyErr.Error()}, nil
		}
		if isMissingBinary(whyErr) {
			res.Note = mergeNotes(res.Note, "audit2why 不可用: "+whyErr.Error())
		}
	}
	if whyBuf.Len() > 0 {
		res.Reason = trimWhyOutput(whyBuf.String())
		res.Confidence = classifyReason(whyBuf.String())
	}

	// 第 3 段:audit2allow --explain 给建议
	var allowBuf bytes.Buffer
	allowErr := s.runStdin(execCtx, audit2allowBinary, record.Bytes(), func(line []byte) bool {
		allowBuf.Write(line)
		allowBuf.WriteByte('\n')
		return true
	}, "--explain")
	if allowErr != nil {
		_, fatal := handleExecError(allowErr)
		if fatal {
			return Explanation{EventID: args.EventID, Note: "audit2allow 调用失败: " + allowErr.Error()}, nil
		}
		if isMissingBinary(allowErr) {
			res.Note = mergeNotes(res.Note, "audit2allow 不可用: "+allowErr.Error())
		}
	}
	if allowBuf.Len() > 0 {
		res.Suggestion = extractAllowRule(allowBuf.String())
	}

	if res.Reason == "" && res.Suggestion == "" && res.Note == "" {
		res.Note = "无可用解释或建议"
	}
	return res, nil
}

// Summary 执行 avc_summary:走 avc_recent 同款 ausearch 拉事件,服务端聚合。
// --summary 不是 ausearch 合法选项,本机实测见 EVIDENCE.md。
func (s *service) Summary(ctx context.Context, args SummaryArgs) (SummaryResult, error) {
	if err := args.Validate(); err != nil {
		return SummaryResult{}, err
	}
	execCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	argv := []string{"-m", "avc,user_avc", "--format", "default"}
	if args.Since != nil && *args.Since != "" {
		argv = append(argv, "-ts", *args.Since)
	}

	var lines [][]byte
	execNote := ""
	err := s.run(execCtx, ausearchBinary, func(line []byte) bool {
		lines = append(lines, append([]byte(nil), line...))
		return true
	}, argv...)
	if err != nil {
		note, fatal := handleExecError(err)
		if fatal {
			return SummaryResult{}, err
		}
		execNote = note
	}

	events := parseAvcEvents(lines)
	buckets := aggregateBuckets(events)
	res := SummaryResult{Total: len(events), Buckets: buckets, Note: execNote}
	return res, nil
}

// aggregateBuckets 把事件按 "scontext|tclass|comm|perm" 分组,返回按 Count
// 降序的桶切片。
func aggregateBuckets(events []AVCEvent) []SummaryBucket {
	if len(events) == 0 {
		return []SummaryBucket{}
	}
	counts := make(map[string]int)
	for _, ev := range events {
		key := strings.Join([]string{ev.SContext, ev.TClass, ev.Comm, ev.Perm}, "|")
		counts[key]++
	}
	out := make([]SummaryBucket, 0, len(counts))
	for k, v := range counts {
		out = append(out, SummaryBucket{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// --- 退出码 / 包装 ---

// execError 是 CLI 非零退出的类型化包装:Code 是子进程真实退出码,Stderr 是
// 子进程 stderr 内容。调用方可用 errors.As 取出 Code 决定按"已安装列表差异"
// / 语义还是真故障上抛。
type execError struct {
	Code   int
	Stderr string
	Cause  error
}

func (e *execError) Error() string {
	return fmt.Sprintf("CLI 退出码 %d: %s", e.Code, strings.TrimSpace(e.Stderr))
}

func (e *execError) Unwrap() error { return e.Cause }

// isMissingBinary 识别"binary 不在"的 ENOENT 降级信号。
func isMissingBinary(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, exec.ErrNotFound)
}

// isAusearchNoMatch 识别 ausearch rc=1 + stderr 含 "<no matches>" 的合法
// 空集信号。本机实测 ausearch --input <empty> -m rc=1 时 stdout 写
// "<no matches>"(实参 stderr 也可能含),按异常 envelope 收 stderr。
func isAusearchNoMatch(err error) bool {
	if err == nil {
		return false
	}
	var ee *execError
	if !errors.As(err, &ee) {
		return false
	}
	return ee.Code == 1 && strings.Contains(ee.Stderr, "<no matches>")
}

// isAuditLogUnavailable 识别 ausearch rc=1 + stderr 含 "Error opening
// /var/log/audit/audit.log" 或 "Error opening config file" 的审计日志不可读
// 信号。两种都是 auditd 未启用 / 配置无访问权限的常见形态。
func isAuditLogUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var ee *execError
	if !errors.As(err, &ee) {
		return false
	}
	if ee.Code != 1 {
		return false
	}
	return strings.Contains(ee.Stderr, "Error opening /var/log/audit") ||
		strings.Contains(ee.Stderr, "Error opening config file")
}

// handleExecError 收敛三只 CLI runner 错误的语义分类:binary 缺失、rc=1+<no
// matches>、rc=1+审计日志不可读均非 fatal,降级为 note;rc≥2 或非 *execError
// 视为真故障,fatal=true 上抛。
//
// 调用方约定:err != nil 且 !fatal 时不得把结果宣称为"干净 / 合法空集"——
// rc=1 已声明某种失败;run 收集到的行后续要按业务解释继续解析。
func handleExecError(err error) (note string, fatal bool) {
	if err == nil {
		return "", false
	}
	if isMissingBinary(err) {
		return "CLI 不可用: " + err.Error(), false
	}
	var ee *execError
	if !errors.As(err, &ee) || ee.Code >= 2 {
		return "", true
	}
	if isAusearchNoMatch(err) {
		return "无匹配 AVC 事件", false
	}
	if isAuditLogUnavailable(err) {
		return "auditd 未启用或审计日志不可访问: " + strings.TrimSpace(ee.Stderr), false
	}
	return "ausearch 报告差异(退出码 1),已按 stdout 解析", false
}

// mergeNotes 合并非空 note;空串跳过,重复同串去重,其余以 "; " 连接。
func mergeNotes(notes ...string) string {
	var kept []string
	for _, n := range notes {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		dup := false
		for _, k := range kept {
			if k == n {
				dup = true
				break
			}
		}
		if !dup {
			kept = append(kept, n)
		}
	}
	return strings.Join(kept, "; ")
}

// --- runCLI / stdinRunner ---

// runCLI 通用 fork 包装:绝对路径 argv 直发(绝不经过 sh -c),逐行把 stdout
// 喂给 onLine。onLine 返回 false 时杀子进程并正常收工。stderr 必须在
// cmd.Start() 之前接好(承接 journal/integrity 教训)。
//
// 退出码语义:
//   - ctx 超时/取消:优先返回 ctx.Err()(DeadlineExceeded / Canceled)。
//   - 任意非零退出:stderr wrap 上抛(envelope 形式:execError{Code,Stderr,Cause})。
//   - run 内部不再加超时:调用方用 context.WithTimeout 派生 execCtx。
func runCLI(ctx context.Context, bin string, onLine func([]byte) bool, args ...string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = nil
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%s stdout 管道失败: %w", bin, err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		if isMissingBinary(err) {
			return err
		}
		return fmt.Errorf("%s 启动失败: %w", bin, err)
	}

	scanner := bufio.NewScanner(stdout)
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

	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if scanErr != nil {
		return fmt.Errorf("%s 读取失败: %w", bin, scanErr)
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			code := exitErr.ExitCode()
			if code != 0 {
				return &execError{Code: code, Stderr: stderr.String(), Cause: waitErr}
			}
		}
		return fmt.Errorf("%s 失败: %w(%s)", bin, waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// stdinRunner 与 runCLI 同形,但额外喂 stdin(用于 audit2why / audit2allow
// 接收 ausearch 提取的记录)。退出码语义与 runCLI 一致。
func stdinRunner(ctx context.Context, bin string, stdin []byte, onLine func([]byte) bool, args ...string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(string(stdin))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%s stdout 管道失败: %w", bin, err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		if isMissingBinary(err) {
			return err
		}
		return fmt.Errorf("%s 启动失败: %w", bin, err)
	}

	scanner := bufio.NewScanner(stdout)
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

	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if scanErr != nil {
		return fmt.Errorf("%s 读取失败: %w", bin, scanErr)
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			code := exitErr.ExitCode()
			if code != 0 {
				return &execError{Code: code, Stderr: stderr.String(), Cause: waitErr}
			}
		}
		return fmt.Errorf("%s 失败: %w(%s)", bin, waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// --- audit2why / audit2allow 输出后处理 ---

// trimWhyOutput 把 audit2why 的输出剥离重复的 audit 行头(它默认会 echo
// 原记录),保留 "Was caused by" 等说明段。
func trimWhyOutput(s string) string {
	var kept []string
	inWhy := false
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		// 跳过 ausearch 风格的"type=AVC msg=audit(...)"前导行
		if strings.HasPrefix(t, "type=") {
			inWhy = true
			continue
		}
		if !inWhy && t == "" {
			continue
		}
		// 进入说明段
		if strings.HasPrefix(t, "Was caused by") || strings.HasPrefix(t, "The") || strings.HasPrefix(t, "Missing") || strings.HasPrefix(t, "You can use") || strings.HasPrefix(t, "allow") {
			kept = append(kept, t)
		} else if len(kept) > 0 {
			kept = append(kept, t)
		}
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}

// classifyReason 把 audit2why 的解释分类为枚举字符串(给 AI 客户端分层提示)。
func classifyReason(s string) string {
	if strings.Contains(s, "Missing type enforcement") {
		return "type_enforcement"
	}
	if strings.Contains(s, "Missing allow rule") {
		return "boolean"
	}
	if strings.Contains(s, "policy version") {
		return "policy_version"
	}
	if strings.Contains(s, "Nothing to do") {
		return "none"
	}
	return "unknown"
}

// extractAllowRule 从 audit2allow --explain 输出中提取核心规则行(以
// "allow <scontext> <tcontext>:<tclass> <perm>;"为输出的),
// 剥离注释与原 reason 行。
func extractAllowRule(s string) string {
	var rules []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") || t == "" {
			continue
		}
		if strings.HasPrefix(t, "allow ") {
			rules = append(rules, t)
		}
	}
	return strings.Join(rules, "\n")
}

// --- 启动期环境探测 ---

// checkStartupEnv 在 daemon 启动期探测三只 CLI 可用性:任意缺失往 stderr 写
// 一次性提示,工具调用时各自降级为 note(不崩)。euid 不直接警告——具备
// AmbientCapabilities=CAP_DAC_READ_SEARCH 的部署态是合规的,euid 仅是提示。
func checkStartupEnv() {
	for _, bin := range []string{ausearchBinary, audit2whyBinary, audit2allowBinary} {
		if _, err := exec.LookPath(bin); err != nil {
			fmt.Fprintf(os.Stderr, "daedalus-avc: %s 不可用 (%v);工具将返回空结果 + note\n", bin, err)
		}
	}
}

// --- 未使用占位(抑制某些 IDE 警告) ---
var _ = strconv.Itoa
