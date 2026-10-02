// triage 启动/崩溃排查基元。一组命令结果集：
//
//   - systemd-analyze blame / critical-chain：开机启动链路时间分布与关键链
//   - journalctl -b -1：上一版启动日志
//   - coredumpctl list / info：内核转储清单 / 单条详情
//
// 安全边界：参数在拼 argv 之前强制校验（unit 字符集 + 路径遍历、priority
// 0..7/名字枚举、coredump_id 仅允许正整数 PID），再经 exec.CommandContext
// 绝对路径 argv 直发，绝不经过 sh -c。所有可选参数一律 "=" 等号形式拼入
// argv，杜绝前导 '-' 被当选项。缺失任一外部命令均优雅降级为空集 + note，
// 绝不 panic。
//
// 退出码语义（5 个工具各异，按实测文档化后缀落钉）：
//   - systemd-analyze blame / critical-chain：rc=0 为成功，stderr 可能含
//     信息性提示；rc≠0 一律视为真错误上抛。
//   - coredumpctl list / info：rc=1 + stderr "No coredumps found." 为合法
//     空集；rc=1 + 其他 stderr 为真错误；rc=other 一律上抛。
//   - journalctl：参考 journal 插件语义，rc≠0 一律上抛。
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

// systemd-analyze 与 coredumpctl 二进制路径为包级变量，以便测试注入假脚本。
var (
	systemdAnalyzeBinary = "/usr/bin/systemd-analyze"
	coredumpctlBinary    = "/usr/bin/coredumpctl"
	journalctlBinary     = "/usr/bin/journalctl"
)

const (
	// triageTimeout 是单次 CLI 调用的兜底上限。与 journal 一致：run 内部不
	// 再加超时，由调用方用 context.WithTimeout 派生 execCtx 再传入。
	triageTimeout = 30 * time.Second

	// blameMaxEntries 是 boot_blame 返回的条数硬上限。
	blameMaxEntries = 50

	// chainMaxDepth 是 boot_critical_chain 单条链深度的截断阈值；命中即
	// 停止继续解析，避免极深单元图把响应拉爆。
	chainMaxDepth = 64

	// lastBootLimit 是 last_boot_log 固定返回的最近条数。
	lastBootLimit = 50

	// coredumpInfoMaxBytes 是 coredump_info 返回的 raw 字段最大字节数，
	// 防止超大 stack trace 把响应拉爆。
	coredumpInfoMaxBytes = 64 * 1024
)

// priorityNames 钉死 syslog PRIORITY 0..7 → 名字枚举。
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

// unitPattern 与 journal 插件一致：首字符字母/数字/下划线，后续字母/数字/
// 下划线/点/@/-。'..' 遍历由 Validate 单独兜底。
var unitPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]*$`)

// coredumpInfoLine 匹配 coredumpctl info 文本输出的 "键: 值" 行。
// 键字符集：字母/数字/空格。值字符集任意（控制字符不允许）。
var coredumpInfoKeyPattern = regexp.MustCompile(`^[[:space:]]*([A-Za-z][A-Za-z ]*):[[:space:]]+(.+)$`)

// 5 个工具的入参与返回类型 ------------------------------

// BootBlameEntry 是 systemd-analyze blame 的单条单元时间。
type BootBlameEntry struct {
	Unit    string  `json:"unit"`
	Time    string  `json:"time"` // 原文 "14.636s"
	Seconds float64 `json:"seconds"`
}

// BootBlameResult 是 boot_blame 的返回载荷。
type BootBlameResult struct {
	Entries []BootBlameEntry `json:"entries"`
	Note    string           `json:"note,omitempty"`
}

// CriticalChainLine 是 systemd-analyze critical-chain 的一行（不含预解析时
// 的树前缀字符）。
type CriticalChainLine struct {
	Unit       string `json:"unit"`
	Depth      int    `json:"depth"`
	Activation string `json:"activation,omitempty"` // @13.272s
	Elapsed    string `json:"elapsed,omitempty"`    // +8.360s
}

// CriticalChainResult 是 boot_critical_chain 的返回载荷。
type CriticalChainResult struct {
	Unit string              `json:"unit,omitempty"` // 请求单元
	Tree []CriticalChainLine `json:"tree"`
	Note string              `json:"note,omitempty"`
}

// LastBootLogEntry 是 last_boot_log 单条记录。
type LastBootLogEntry struct {
	Timestamp string `json:"timestamp"`
	Priority  string `json:"priority"`
	Unit      string `json:"unit,omitempty"`
	Message   string `json:"message"`
}

// LastBootLogResult 是 last_boot_log 的返回载荷。
type LastBootLogResult struct {
	Entries []LastBootLogEntry `json:"entries"`
	Note    string             `json:"note,omitempty"`
}

// CoredumpEntry 是 coredumpctl list --json=short 的单条记录。
type CoredumpEntry struct {
	Time         string `json:"time"` // RFC3339Nano
	PID          int64  `json:"pid"`
	UID          int64  `json:"uid"`
	GID          int64  `json:"gid"`
	Signal       int64  `json:"signal"`
	CoredumpFile string `json:"coredump_file,omitempty"` // present / inaccessible / none
	Exe          string `json:"exe"`
	SizeBytes    *int64 `json:"size_bytes,omitempty"` // null 时省略（不可达）
}

// CoredumpsListResult 是 coredumps_list 的返回载荷。
type CoredumpsListResult struct {
	Entries []CoredumpEntry `json:"entries"`
	Note    string          `json:"note,omitempty"`
}

// CoredumpInfoResult 是 coredump_info 的返回载荷。Raw 字段保留完整原文，
// Fields 字段为按 "Key: Value" 切分的扁平 map（首条命中为序）。
type CoredumpInfoResult struct {
	CoredumpID string            `json:"coredump_id"`
	Fields     map[string]string `json:"fields"`
	Raw        string            `json:"raw"`
	Note       string            `json:"note,omitempty"`
}

// CriticalChainArgs 是 boot_critical_chain 的可选入参：Unit 为空时不传，
// systemd-analyze 默认输出当前默认目标的链。
type CriticalChainArgs struct {
	Unit string
}

// LastBootLogArgs 是 last_boot_log 的可选入参：Priority 为空时不过滤。
type LastBootLogArgs struct {
	Priority *string
}

// Validate 校验 critical_chain 的 unit 字符集。
func (a CriticalChainArgs) Validate() error {
	if a.Unit == "" {
		return nil
	}
	if !unitPattern.MatchString(a.Unit) {
		return fmt.Errorf("非法 unit: %q", a.Unit)
	}
	if strings.Contains(a.Unit, "..") {
		return fmt.Errorf("非法 unit(路径遍历): %q", a.Unit)
	}
	return nil
}

// Validate 校验 last_boot_log 的 priority 枚举（与 journal 插件一致）。
func (a LastBootLogArgs) Validate() error {
	if a.Priority == nil || *a.Priority == "" {
		return nil
	}
	if _, ok := priorityNames[*a.Priority]; ok {
		return nil
	}
	for _, name := range priorityNames {
		if name == *a.Priority {
			return nil
		}
	}
	return fmt.Errorf("priority 非法: %q(应为 0..7 或 emerg..debug)", *a.Priority)
}

// ValidateCoredumpID 校验 coredump_info 的 coredump_id：仅接受正整数 PID，
// 且限 int32 范围（Linux PID 上限）。coredumpctl info 也接受 "@<timestamp>"
// 或正则匹配式，但两者攻击面更广；本任务面严格限于正整数 PID。
func ValidateCoredumpID(id string) error {
	if id == "" {
		return errors.New("coredump_id 不能为空")
	}
	n, err := strconv.ParseInt(id, 10, 32)
	if err != nil || n <= 0 {
		return fmt.Errorf("非法 coredump_id: %q(应为正整数 PID,int32 范围)", id)
	}
	return nil
}

// execRunner 是外部 CLI 调用的注入点。生产实现是 runCLI。bin 参数允许
// 测试注入任意假脚本。
type execRunner func(ctx context.Context, bin string, onLine func([]byte) bool, args ...string) error

// service 持有 CLI 调用器与超时。
type service struct {
	run     execRunner
	timeout time.Duration
}

func newService() *service {
	return &service{run: runCLI, timeout: triageTimeout}
}

// BootBlame 执行 systemd-analyze blame：解析 " <time>s <unit>" 格式。
// 缺 systemd-analyze 降级为空集 + note；rc≠0 一律视为真错误。
func (s *service) BootBlame(ctx context.Context) BootBlameResult {
	execCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var lines [][]byte
	err := s.run(execCtx, systemdAnalyzeBinary, func(line []byte) bool {
		lines = append(lines, append([]byte(nil), line...))
		return true
	}, "blame")
	if err != nil {
		if isMissingBinary(err) {
			return BootBlameResult{Entries: []BootBlameEntry{}, Note: "systemd-analyze 不可用: " + err.Error()}
		}
		return BootBlameResult{Entries: []BootBlameEntry{}, Note: "systemd-analyze 调用失败: " + err.Error()}
	}

	entries := parseBlame(lines)
	res := BootBlameResult{Entries: entries}
	if len(entries) > blameMaxEntries {
		res.Entries = entries[:blameMaxEntries]
		res.Note = fmt.Sprintf("输出 %d 条,已截断保留前 %d 条", len(entries), blameMaxEntries)
	}
	return res
}

// BootCriticalChain 执行 systemd-analyze critical-chain [unit]：解析树
// 形输出。unit 为空时不传。
func (s *service) BootCriticalChain(ctx context.Context, args CriticalChainArgs) (CriticalChainResult, error) {
	if err := args.Validate(); err != nil {
		return CriticalChainResult{}, err
	}
	execCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	argv := []string{"critical-chain"}
	if args.Unit != "" {
		argv = append(argv, args.Unit)
	}

	var lines [][]byte
	err := s.run(execCtx, systemdAnalyzeBinary, func(line []byte) bool {
		lines = append(lines, append([]byte(nil), line...))
		return true
	}, argv...)
	if err != nil {
		if isMissingBinary(err) {
			return CriticalChainResult{Tree: []CriticalChainLine{}, Unit: args.Unit, Note: "systemd-analyze 不可用: " + err.Error()}, nil
		}
		return CriticalChainResult{}, err
	}

	tree, skipped := parseCriticalChain(lines)
	res := CriticalChainResult{Unit: args.Unit, Tree: tree}
	if skipped > 0 {
		res.Note = fmt.Sprintf("跳过 %d 行非预期格式", skipped)
	}
	return res, nil
}

// LastBootLog 执行 journalctl -b -1 -o json -n lastBootLimit。
// 缺 journalctl 降级为空集 + note；rc≠0 一律上抛。
func (s *service) LastBootLog(ctx context.Context, args LastBootLogArgs) (LastBootLogResult, error) {
	if err := args.Validate(); err != nil {
		return LastBootLogResult{}, err
	}
	execCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	argv := []string{"-b", "-1", "-n", strconv.Itoa(lastBootLimit), "-o", "json", "--no-pager", "-q"}
	if args.Priority != nil && *args.Priority != "" {
		argv = append(argv, "--priority="+*args.Priority)
	}

	var lines [][]byte
	err := s.run(execCtx, journalctlBinary, func(line []byte) bool {
		lines = append(lines, append([]byte(nil), line...))
		return true
	}, argv...)
	if err != nil {
		if isMissingBinary(err) {
			return LastBootLogResult{Entries: []LastBootLogEntry{}, Note: "journalctl 不可用: " + err.Error()}, nil
		}
		return LastBootLogResult{Entries: []LastBootLogEntry{}, Note: "journalctl 调用失败: " + err.Error()}, nil
	}

	entries, skipped := parseJournalEntries(lines)
	res := LastBootLogResult{Entries: entries}
	if skipped > 0 {
		res.Note = fmt.Sprintf("跳过 %d 行坏 JSON", skipped)
	}
	return res, nil
}

// CoredumpsList 执行 coredumpctl list --json=short --no-pager，解析 JSON 数组。
// rc=1 + stderr "No coredumps found." 视为合法空集；rc=1 + 其他 stderr 视为
// 真错误。缺 coredumpctl 降级为空集 + note。
func (s *service) CoredumpsList(ctx context.Context) CoredumpsListResult {
	execCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var lines [][]byte
	err := s.run(execCtx, coredumpctlBinary, func(line []byte) bool {
		lines = append(lines, append([]byte(nil), line...))
		return true
	}, "list", "--json=short", "--no-pager", "-q")
	if err != nil {
		if isCoredumpsEmpty(err) {
			return CoredumpsListResult{Entries: []CoredumpEntry{}, Note: "无内核转储记录"}
		}
		if isMissingBinary(err) {
			return CoredumpsListResult{Entries: []CoredumpEntry{}, Note: "coredumpctl 不可用: " + err.Error()}
		}
		return CoredumpsListResult{Entries: []CoredumpEntry{}, Note: "coredumpctl 调用失败: " + err.Error()}
	}

	entries, err := parseCoredumpsJSON(lines)
	if err != nil {
		return CoredumpsListResult{Entries: []CoredumpEntry{}, Note: "coredumpctl list JSON 解析失败: " + err.Error()}
	}
	return CoredumpsListResult{Entries: entries}
}

// CoredumpInfo 执行 coredumpctl info <id> --no-pager，按 "Key: Value"
// 行解析并保留 raw 全文（截断至 coredumpInfoMaxBytes）。
func (s *service) CoredumpInfo(ctx context.Context, id string) (CoredumpInfoResult, error) {
	if err := ValidateCoredumpID(id); err != nil {
		return CoredumpInfoResult{}, err
	}
	execCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var lines [][]byte
	err := s.run(execCtx, coredumpctlBinary, func(line []byte) bool {
		lines = append(lines, append([]byte(nil), line...))
		return true
	}, "info", id, "--no-pager")
	if err != nil {
		if isCoredumpsEmpty(err) {
			return CoredumpInfoResult{CoredumpID: id, Fields: map[string]string{}, Raw: "", Note: "无内核转储记录"}, nil
		}
		if isMissingBinary(err) {
			return CoredumpInfoResult{CoredumpID: id, Fields: map[string]string{}, Raw: "", Note: "coredumpctl 不可用: " + err.Error()}, nil
		}
		return CoredumpInfoResult{CoredumpID: id, Fields: map[string]string{}, Raw: "", Note: "coredumpctl 调用失败: " + err.Error()}, nil
	}

	raw := string(bytes.Join(lines, []byte("\n")))
	fields := parseCoredumpInfo(lines)
	if len(raw) > coredumpInfoMaxBytes {
		raw = raw[:coredumpInfoMaxBytes] + "\n... [truncated]"
	}
	return CoredumpInfoResult{CoredumpID: id, Fields: fields, Raw: raw}, nil
}

// isMissingBinary 识别 "binary 不在" 的 ENOENT 降级信号。
func isMissingBinary(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, exec.ErrNotFound)
}

// isCoredumpsEmpty 识别 coredumpctl rc=1 + stderr "No coredumps found."
// 的合法空集信号。本机实测：coredumpctl list/info 在无匹配时返回 rc=1
// + stderr 一行 "No coredumps found."。其他 rc=1 必须视为真错误。
func isCoredumpsEmpty(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "No coredumps found.")
}

// runCLI 通用 fork 包装：绝对路径 argv 直发（绝不经过 sh -c），逐行把
// stdout 喂给 onLine。onLine 返回 false 时杀子进程并正常收工。
//
// 退出码语义（与 journal 插件一致）：
//   - ctx 超时/取消：优先返回 ctx.Err()。
//   - 任意非零退出：stderr wrap 上抛。
//   - run 内部不再加超时：调用方用 context.WithTimeout 派生 execCtx。
func runCLI(ctx context.Context, bin string, onLine func([]byte) bool, args ...string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = nil
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%s stdout 管道失败: %w", bin, err)
	}
	var stderr bytes.Buffer

	if err := cmd.Start(); err != nil {
		// 区分二进制不存在（ENOENT）与其他启动错误：ENOENT 走 isMissingBinary
		// 优雅降级路径；其他（如权限拒绝）也归到 missing 处理（policy 一致）。
		if isMissingBinary(err) {
			return err
		}
		return fmt.Errorf("%s 启动失败: %w", bin, err)
	}

	cmd.Stderr = &stderr

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
		return fmt.Errorf("%s 失败: %w(%s)", bin, waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// parseBlame 解析 " <time>s <unit>" 格式；坏行跳过。time 单位保留原文，
// 同时转 float 秒用于客户端排序。
func parseBlame(lines [][]byte) []BootBlameEntry {
	out := make([]BootBlameEntry, 0, len(lines))
	for _, line := range lines {
		s := strings.TrimSpace(string(line))
		if s == "" {
			continue
		}
		// "14.636s sys-module-fuse.device" → [time, unit]
		parts := strings.SplitN(s, " ", 2)
		if len(parts) != 2 {
			continue
		}
		timeStr := strings.TrimSuffix(parts[0], "s")
		seconds, err := strconv.ParseFloat(timeStr, 64)
		if err != nil {
			continue
		}
		out = append(out, BootBlameEntry{
			Unit:    parts[1],
			Time:    parts[0],
			Seconds: seconds,
		})
	}
	return out
}

// parseCriticalChain 解析 critical-chain 树形输出。行形态：
//
//	multi-user.target @13.272s              // 根，无树前缀
//	└─docker.service @4.911s +8.360s        // 子节点，depth=1
//	  └─containerd.service @3.443s +1.460s  // depth=2
//
// 深度 = 行首前缀 rune 数 / 2（每级缩进恰为 2 个 rune：空格 + 树符）。
// 说明性前言行（"The time when unit ..."）第二个 token 不以 "@" 开头，
// 不是合法链路行，直接跳过。
func parseCriticalChain(lines [][]byte) ([]CriticalChainLine, int) {
	out := make([]CriticalChainLine, 0, len(lines))
	skipped := 0
	for _, raw := range lines {
		s := strings.TrimRight(string(raw), " \t\r")
		if s == "" {
			continue
		}
		runes := []rune(s)
		i := 0
		for i < len(runes) && isTreePrefixRune(runes[i]) {
			i++
		}
		depth := i / 2
		rest := strings.TrimSpace(string(runes[i:]))
		parts := strings.Fields(rest)
		// 链路行须形如 "<unit> @<t>s [+<t>s]"；第 2 个 token 必须以 "@"
		// 开头（说明性前言行不满足）。
		if len(parts) < 2 || !strings.HasPrefix(parts[1], "@") {
			skipped++
			continue
		}
		unit := parts[0]
		activation := parts[1]
		var elapsed string
		if len(parts) >= 3 && strings.HasPrefix(parts[2], "+") {
			elapsed = parts[2]
		}
		out = append(out, CriticalChainLine{
			Unit:       unit,
			Depth:      depth,
			Activation: activation,
			Elapsed:    elapsed,
		})
		if depth >= chainMaxDepth {
			break
		}
	}
	return out, skipped
}

// isTreePrefixRune 判定 critical-chain 行首前缀字符：缩进空格与树符。
func isTreePrefixRune(c rune) bool {
	return c == ' ' || c == '└' || c == '├' || c == '─'
}

// parseJournalEntries 复用 journal 插件的 JSONL 解析格式（仅取排障常用列）。
func parseJournalEntries(lines [][]byte) ([]LastBootLogEntry, int) {
	out := make([]LastBootLogEntry, 0, len(lines))
	skipped := 0
	for _, line := range lines {
		e, ok := parseJournalEntry(line)
		if !ok {
			skipped++
			continue
		}
		out = append(out, e)
	}
	return out, skipped
}

// parseJournalEntry 与 journal.go 内的 parseEntry 等价，独立实现以避免
// 跨插件共享子包（AGENTS 反模式）。
func parseJournalEntry(line []byte) (LastBootLogEntry, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return LastBootLogEntry{}, false
	}
	tsRaw, ok := raw["__REALTIME_TIMESTAMP"]
	if !ok {
		return LastBootLogEntry{}, false
	}
	us, err := strconv.ParseInt(rawToString(tsRaw), 10, 64)
	if err != nil {
		return LastBootLogEntry{}, false
	}
	return LastBootLogEntry{
		Timestamp: time.Unix(0, us*1000).UTC().Format(time.RFC3339Nano),
		Priority:  priorityNames[rawToString(raw["PRIORITY"])],
		Unit:      rawToString(raw["_SYSTEMD_UNIT"]),
		Message:   rawToString(raw["MESSAGE"]),
	}, true
}

// parseCoredumpsJSON 把 coredumpctl list --json=short 的所有行合并为单一
// JSON 数组后解析。本机实测每行一条独立对象，因此 "[" + \n + "]" 拼接即可。
// 也兼容单行数组输出。
func parseCoredumpsJSON(lines [][]byte) ([]CoredumpEntry, error) {
	if len(lines) == 0 {
		return []CoredumpEntry{}, nil
	}
	joined := bytes.Join(lines, []byte("\n"))
	trimmed := bytes.TrimSpace(joined)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return []CoredumpEntry{}, nil
	}
	// 兼容两种输出形态：单行数组 vs 多行 JSONL。
	if trimmed[0] != '[' {
		// JSONL 形态：包成数组再解。
		trimmed = append([]byte{'['}, append(trimmed, ']')...)
	}
	var raw []map[string]any
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return nil, fmt.Errorf("JSON 解析失败: %w", err)
	}
	out := make([]CoredumpEntry, 0, len(raw))
	for _, r := range raw {
		out = append(out, mapCoredumpEntry(r))
	}
	return out, nil
}

// mapCoredumpEntry 把 coredumpctl list 的 JSON 字段映射到 CoredumpEntry。
// time 字段为微秒整数；size 字段为字节（无权限时为 null）。
func mapCoredumpEntry(r map[string]any) CoredumpEntry {
	entry := CoredumpEntry{
		CoredumpFile: rawToString(asRaw(r["corefile"])),
		Exe:          rawToString(asRaw(r["exe"])),
	}
	if v, ok := r["time"]; ok {
		us := toInt64(v)
		entry.Time = time.Unix(0, us*1000).UTC().Format(time.RFC3339Nano)
	}
	if v, ok := r["pid"]; ok {
		entry.PID = toInt64(v)
	}
	if v, ok := r["uid"]; ok {
		entry.UID = toInt64(v)
	}
	if v, ok := r["gid"]; ok {
		entry.GID = toInt64(v)
	}
	if v, ok := r["sig"]; ok {
		entry.Signal = toInt64(v)
	}
	if v, ok := r["size"]; ok && v != nil {
		sz := toInt64(v)
		entry.SizeBytes = &sz
	}
	return entry
}

// parseCoredumpInfo 按行解析 coredumpctl info 的 "Key: Value" 文本。多行
// 值（如 Message、Stack trace）保留为上一键的延续（合并到 raw 字段）。
// 此处仅把每个按键的首次值写入 Fields 字段。
func parseCoredumpInfo(lines [][]byte) map[string]string {
	out := make(map[string]string)
	for _, raw := range lines {
		s := strings.TrimRight(string(raw), " \t\r")
		if s == "" {
			continue
		}
		m := coredumpInfoKeyPattern.FindStringSubmatch(s)
		if len(m) != 3 {
			continue
		}
		key := strings.TrimSpace(m[1])
		val := strings.TrimSpace(m[2])
		// 首键仅记录首次。
		if _, exists := out[key]; !exists {
			out[key] = val
		}
	}
	return out
}

// asRaw 把 any 还原为 json.RawMessage（用于嵌套 map 中的标量）。
func asRaw(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case string:
		return json.RawMessage(strconv.Quote(x))
	case float64:
		return json.RawMessage(strconv.FormatFloat(x, 'f', -1, 64))
	case bool:
		if x {
			return json.RawMessage("true")
		}
		return json.RawMessage("false")
	default:
		// 兜底：交给 encoding/json。
		b, _ := json.Marshal(x)
		return b
	}
}

// toInt64 把 any 强转为 int64，容忍 float64 (JSON 数字默认形态)。
func toInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	case json.Number:
		i, _ := x.Int64()
		return i
	case string:
		i, _ := strconv.ParseInt(x, 10, 64)
		return i
	}
	return 0
}

// rawToString 把 JSON 标量还原为字符串：字符串去引号，数字/布尔取字面量，
// 字节数组形态按字节还原。
func rawToString(r json.RawMessage) string {
	if len(r) == 0 {
		return ""
	}
	trimmed := bytes.TrimSpace(r)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
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
