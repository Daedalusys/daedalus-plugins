// Command daedalus-trace 是审计链回放视图 MCP 服务器(stdio JSON-RPC,只读)。
//
// 把现有 audit.jsonl 渲染成可读的工具调用时间线:trace_session(按调用者
// 身份)/ trace_tool(按工具名)/ trace_tx(单事务完整回放)/ trace_summary
// (总体统计)。视图层与写入层职责切分:本服务器只读不改,完整性校验
// (哈希链重算)是 daedalus-audit verify 的职责。
//
// 安全边界:零 exec、零写入;过滤值是纯字符串等值比较,永不进入 argv 或
// 路径拼接;数据源路径解析链固定(env → /var/log/daedalus → $HOME 兜底)。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/version"
)

const serverName = "daedalus-trace"

func main() {
	server := newServer()

	// SIGINT/SIGTERM 触发优雅退出;Run 返回后错误信息写 stderr,
	// 以保持 stdout 的 JSON-RPC 数据流完整。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !isCleanShutdown(err) {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
	}
}

// isCleanShutdown 判定"正常结束":stdin 客户端断开(context.Canceled / EOF)与
// SDK 内部 jsonrpc2.ErrServerClosing("server is closing: ...")。
// ErrServerClosing 位于 internal 包无法用 errors.Is 匹配,按消息前缀归类。
func isCleanShutdown(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return true
	}
	return strings.HasPrefix(err.Error(), "server is closing")
}

// paginationProps 是 trace_session/trace_tool 共享的时间界+游标+条数上限
// 可选参数集(镜像两工具同构的分页面;required 由各工具单独追加)。
func paginationProps() map[string]*jsonschema.Schema {
	return map[string]*jsonschema.Schema{
		"since":  {Type: "string", Description: "RFC3339 时间下界(含),省略则不限制。"},
		"until":  {Type: "string", Description: "RFC3339 时间上界(含),省略则不限制。"},
		"cursor": {Type: "integer", Description: "行号游标:仅回放 line_no > cursor 的记录;用回包 next_cursor 续传,0/省略从头开始。"},
		"limit":  {Type: "integer", Description: fmt.Sprintf("单次返回条目上限,范围 [1, %d],缺省 %d。", maxLimit, defaultLimit)},
	}
}

func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	// go-sdk 的 DestructiveHint/OpenWorldHint 为 *bool 且 SDK 未导出取址
	// 助手,按实证形态用局部变量取址(只读视图必然非破坏性、封闭世界)。
	nonDestructive := false
	closedWorld := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}

	sessionProps := paginationProps()
	sessionProps["session_id"] = &jsonschema.Schema{
		Type:        "string",
		Description: "调用者身份(audit 记录 identity 字段,例如 daedalus-copilot / daedalus-host / daedalus-tx / cli),等值匹配。",
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "trace_session",
		Description: "只读回放指定调用者身份的审计时间线。\n\n通过流式扫描 audit.jsonl(env → /var/log/daedalus → $HOME 兜底解析链)返回 identity 等值匹配的条目序列。\n\n参数：\n    session_id: 必填,调用者身份(等值匹配 identity 字段)。\n    since/until: RFC3339 时间界(可选)。\n    cursor/limit: 行号游标分页(可选)。\n\n返回：\n    {log_path, session_id, entries[], next_cursor, scanned_lines, matched_total, malformed_skipped}。",
		InputSchema: &jsonschema.Schema{
			Type:       "object",
			Properties: sessionProps,
			Required:   []string{"session_id"},
		},
		Annotations: annotations,
	}, handleTraceSession)

	toolProps := paginationProps()
	toolProps["tool_name"] = &jsonschema.Schema{
		Type:        "string",
		Description: "工具名(audit 记录 tool 字段,例如 fs.read_file / shell_exec),等值匹配。",
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "trace_tool",
		Description: "只读回放指定工具名的审计时间线。\n\n通过流式扫描 audit.jsonl 返回 tool 等值匹配的条目序列,支持时间界与游标分页。\n\n参数：\n    tool_name: 必填,工具名(等值匹配)。\n    since/until: RFC3339 时间界(可选)。\n    cursor/limit: 行号游标分页(可选)。\n\n返回：\n    {log_path, tool_name, entries[], next_cursor, scanned_lines, matched_total, malformed_skipped}。",
		InputSchema: &jsonschema.Schema{
			Type:       "object",
			Properties: toolProps,
			Required:   []string{"tool_name"},
		},
		Annotations: annotations,
	}, handleTraceTool)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "trace_tx",
		Description: "只读完整回放单个事务(propose→apply→rollback 全部 step)。\n\n通过扫描 audit.jsonl 收集 tx_id 等值匹配的全部条目(不分页),并给出 tx 二级链创世点与相邻步链连续性判定。\n\n参数：\n    tx_id: 必填,事务 ID。\n\n返回：\n    {log_path, tx_id, step_count, tx_genesis_prev_hash, tx_chain_valid, entries[]};tx 不存在则报错。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"tx_id": {Type: "string", Description: "要回放的事务 ID(audit 记录 tx_id 字段)。"},
			},
			Required: []string{"tx_id"},
		},
		Annotations: annotations,
	}, handleTraceTx)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "trace_summary",
		Description: "只读统计审计链总体画像(调用量/工具分布/失败率)。\n\n通过流式扫描 audit.jsonl 聚合计数(不驻留条目),时间界可选。\n\n参数:仅 since/until(RFC3339 时间界,均可选)。\n\n返回：\n    {log_path, total, first_timestamp, last_timestamp, by_tool, by_outcome, by_identity, tx_count, failure_rate, scanned_lines, malformed_skipped}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"since": {Type: "string", Description: "RFC3339 时间下界(含),省略则不限制。"},
				"until": {Type: "string", Description: "RFC3339 时间上界(含),省略则不限制。"},
			},
		},
		Annotations: annotations,
	}, handleTraceSummary)

	return server
}

// textResult 构造成功结果(单文本块);家族约定:helper 各服务器各持本地副本。
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// jsonResult 输出 indent=2、不转义 HTML 的 JSON 文本块(家族统一形态)。
func jsonResult(v any) *mcp.CallToolResult {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return raisedError("jsonResult", err)
	}
	return textResult(strings.TrimSuffix(buf.String(), "\n"))
}

// raisedError 构造 isError=true 的工具错误结果,文本形态与家族其余
// 服务器一致:"Error executing tool <name>: <消息>"。
func raisedError(tool string, err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error executing tool %s: %v", tool, err)}},
		IsError: true,
	}
}
