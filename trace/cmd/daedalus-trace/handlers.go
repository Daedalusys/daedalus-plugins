// trace 四工具的入参解析、视图载荷与处理器:trace_session / trace_tool /
// trace_tx / trace_summary。扫描/过滤/游标机制住在 scan.go;本文件零 exec、
// 零写入。会话维度说明:audit.jsonl 无独立 session 字段,identity(调用者
// 身份,如 daedalus-copilot / daedalus-host / daedalus-tx / cli)即现状下
// 唯一的时间线归属维度,trace_session 按 identity 等值过滤(032 会话侧视图
// 落地后再演进语义,不预留空转参数)。
package main

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// 分页缺省与上限:limit 超上限即拒绝(而非静默截断),防"顺手全量拉取"。
const (
	defaultLimit = 100
	maxLimit     = 500
)

type traceSessionIn struct {
	SessionID string  `json:"session_id"`
	Since     *string `json:"since"`
	Until     *string `json:"until"`
	Cursor    *int64  `json:"cursor"`
	Limit     *int    `json:"limit"`
}

type traceToolIn struct {
	ToolName string  `json:"tool_name"`
	Since    *string `json:"since"`
	Until    *string `json:"until"`
	Cursor   *int64  `json:"cursor"`
	Limit    *int    `json:"limit"`
}

type traceTxIn struct {
	TxID string `json:"tx_id"`
}

type traceSummaryIn struct {
	Since *string `json:"since"`
	Until *string `json:"until"`
}

// 视图载荷:scanOutcome 为匿名内嵌(JSON 字段提升到外层)。
type sessionView struct {
	LogPath   string `json:"log_path"`
	SessionID string `json:"session_id"`
	scanOutcome
}

type toolView struct {
	LogPath  string `json:"log_path"`
	ToolName string `json:"tool_name"`
	scanOutcome
}

type txView struct {
	LogPath    string       `json:"log_path"`
	TxID       string       `json:"tx_id"`
	StepCount  int64        `json:"step_count"`
	Genesis    string       `json:"tx_genesis_prev_hash"`
	ChainValid bool         `json:"tx_chain_valid"`
	Entries    []traceEntry `json:"entries"`
}

// summaryView 是总体统计;FailureRate = 非 success 条目占比。
type summaryView struct {
	LogPath          string           `json:"log_path"`
	Total            int64            `json:"total"`
	FirstTimestamp   string           `json:"first_timestamp"`
	LastTimestamp    string           `json:"last_timestamp"`
	ByTool           map[string]int64 `json:"by_tool"`
	ByOutcome        map[string]int64 `json:"by_outcome"`
	ByIdentity       map[string]int64 `json:"by_identity"`
	TxCount          int              `json:"tx_count"`
	FailureRate      float64          `json:"failure_rate"`
	ScannedLines     int64            `json:"scanned_lines"`
	MalformedSkipped int64            `json:"malformed_skipped"`
}

// resolveBounds 解析 since/until/cursor/limit 公共分页参数。
func resolveBounds(since, until *string, cursor *int64, limit *int) (viewFilter, int64, int, error) {
	var f viewFilter
	var err error
	if since != nil {
		if f.since, err = parseTimeBound("since", *since); err != nil {
			return f, 0, 0, err
		}
	}
	if until != nil {
		if f.until, err = parseTimeBound("until", *until); err != nil {
			return f, 0, 0, err
		}
	}
	if !f.since.IsZero() && !f.until.IsZero() && f.until.Before(f.since) {
		return f, 0, 0, fmt.Errorf("trace: until(%s) 早于 since(%s)",
			f.until.Format(time.RFC3339), f.since.Format(time.RFC3339))
	}
	outCursor := int64(0)
	if cursor != nil {
		if *cursor < 0 {
			return f, 0, 0, fmt.Errorf("trace: cursor 不能为负: %d", *cursor)
		}
		outCursor = *cursor
	}
	outLimit := defaultLimit
	if limit != nil {
		if *limit < 1 || *limit > maxLimit {
			return f, 0, 0, fmt.Errorf("trace: limit 须在 [1, %d]: %d", maxLimit, *limit)
		}
		outLimit = *limit
	}
	return f, outCursor, outLimit, nil
}

func handleTraceSession(ctx context.Context, _ *mcp.CallToolRequest, in traceSessionIn) (*mcp.CallToolResult, any, error) {
	const toolName = "trace_session"
	if err := validateViewID("session_id", in.SessionID); err != nil {
		return raisedError(toolName, err), nil, nil
	}
	f, cursor, limit, err := resolveBounds(in.Since, in.Until, in.Cursor, in.Limit)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	f.sessionID = in.SessionID
	logPath, out, err := scanOrErr(f, cursor, limit)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	return jsonResult(sessionView{LogPath: logPath, SessionID: in.SessionID, scanOutcome: *out}), nil, nil
}

func handleTraceTool(ctx context.Context, _ *mcp.CallToolRequest, in traceToolIn) (*mcp.CallToolResult, any, error) {
	const toolName = "trace_tool"
	if err := validateViewID("tool_name", in.ToolName); err != nil {
		return raisedError(toolName, err), nil, nil
	}
	f, cursor, limit, err := resolveBounds(in.Since, in.Until, in.Cursor, in.Limit)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	f.toolName = in.ToolName
	logPath, out, err := scanOrErr(f, cursor, limit)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	return jsonResult(toolView{LogPath: logPath, ToolName: in.ToolName, scanOutcome: *out}), nil, nil
}

// handleTraceTx 单事务完整回放:不设分页(回放语义即"全部 step"),
// 零命中视为事务不存在而报错(fail-closed,不返回空壳)。
// ChainValid 是同事务相邻条目 tx_prev_hash == 前一条 entry_hash 的链
// 连续性目测(创世条目的 tx_prev_hash 指向全局链,无法在本视图内验证)。
func handleTraceTx(ctx context.Context, _ *mcp.CallToolRequest, in traceTxIn) (*mcp.CallToolResult, any, error) {
	const toolName = "trace_tx"
	if err := validateViewID("tx_id", in.TxID); err != nil {
		return raisedError(toolName, err), nil, nil
	}
	logPath, err := resolveAuditLog()
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	out, err := scanAuditLog(logPath, 0, viewFilter{txID: in.TxID}, math.MaxInt)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	if out.MatchedTotal == 0 {
		return raisedError(toolName, fmt.Errorf("tx %s 未找到", in.TxID)), nil, nil
	}
	chainValid := true
	for i := 1; i < len(out.Entries); i++ {
		if out.Entries[i].TxPrevHash != out.Entries[i-1].EntryHash {
			chainValid = false
			break
		}
	}
	return jsonResult(txView{
		LogPath: logPath, TxID: in.TxID, StepCount: out.MatchedTotal,
		Genesis: out.Entries[0].TxPrevHash, ChainValid: chainValid, Entries: out.Entries,
	}), nil, nil
}

func handleTraceSummary(ctx context.Context, _ *mcp.CallToolRequest, in traceSummaryIn) (*mcp.CallToolResult, any, error) {
	const toolName = "trace_summary"
	var f viewFilter
	if in.Since != nil {
		var err error
		if f.since, err = parseTimeBound("since", *in.Since); err != nil {
			return raisedError(toolName, err), nil, nil
		}
	}
	if in.Until != nil {
		var err error
		if f.until, err = parseTimeBound("until", *in.Until); err != nil {
			return raisedError(toolName, err), nil, nil
		}
	}
	if !f.since.IsZero() && !f.until.IsZero() && f.until.Before(f.since) {
		return raisedError(toolName, fmt.Errorf("until 早于 since")), nil, nil
	}
	logPath, err := resolveAuditLog()
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	view, err := summarizeAuditLog(logPath, f)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	return jsonResult(view), nil, nil
}

// scanOrErr 解析路径 + 执行扫描的公共两步串联。
func scanOrErr(f viewFilter, cursor int64, limit int) (string, *scanOutcome, error) {
	logPath, err := resolveAuditLog()
	if err != nil {
		return "", nil, err
	}
	out, err := scanAuditLog(logPath, cursor, f, limit)
	if err != nil {
		return "", nil, err
	}
	return logPath, out, nil
}

// summarizeAuditLog 聚合统计:只计数不驻留条目(与 scanAuditLog 同一套
// 行解析与过滤判据,统计口径与时间线视图严格一致)。
func summarizeAuditLog(logPath string, f viewFilter) (*summaryView, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("trace: 打开审计日志失败: %w", err)
	}
	defer file.Close()

	view := &summaryView{
		LogPath: logPath, ByTool: map[string]int64{},
		ByOutcome: map[string]int64{}, ByIdentity: map[string]int64{},
	}
	txSeen := map[string]bool{}
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for lineNo := int64(1); sc.Scan(); lineNo++ {
		view.ScannedLines = lineNo
		e, ok := parseTraceEntry(strings.TrimSpace(sc.Text()), lineNo)
		if !ok {
			view.MalformedSkipped++
			continue
		}
		if !entryMatches(e, f) {
			continue
		}
		view.Total++
		view.ByTool[e.Tool]++
		view.ByOutcome[e.Outcome]++
		view.ByIdentity[e.Identity]++
		if view.FirstTimestamp == "" {
			view.FirstTimestamp = e.Timestamp
		}
		view.LastTimestamp = e.Timestamp
		if e.TxID != "" && !txSeen[e.TxID] {
			txSeen[e.TxID] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("trace: 读取审计日志失败: %w", err)
	}
	view.TxCount = len(txSeen)
	if view.Total > 0 {
		failed := view.Total - view.ByOutcome["success"]
		view.FailureRate = float64(failed) / float64(view.Total)
	}
	return view, nil
}
