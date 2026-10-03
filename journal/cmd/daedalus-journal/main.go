// Command daedalus-journal 是 journald 只读观测能力 MCP 服务器(stdio JSON-RPC)。
//
// 提供 3 个 L0 工具:结构化查询(journal_query)、有界订阅(journal_follow)、
// 上次启动日志(journal_last_boot),全部直 fork journalctl -o json。零写入;
// 缺 journalctl 一律优雅降级为空集 + note。
//
// 安全边界:全部过滤参数在拼 argv 前强制校验(见 journal.go),再经绝对路径
// argv 直发,绝不经过 sh -c。工具名与 manifest.tools 逐字一致(76 脚本构建期
// 交叉核对 manifest ↔ 二进制 tools/list,漂移即构建失败)。
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

const serverName = "daedalus-journal"

// emptyIn 是无参工具(journal_last_boot)的输入类型(客户端 arguments 必须是
// JSON 对象)。
type emptyIn struct{}

// noArgsSchema 对应无参工具的 {"type": "object"} 输入模式。
var noArgsSchema = &jsonschema.Schema{Type: "object"}

// journalQueryIn 是 journal_query 的 MCP 入参(指针字段区分"未给"与"给空")。
type journalQueryIn struct {
	Unit     *string `json:"unit,omitempty"`
	Since    *string `json:"since,omitempty"`
	Until    *string `json:"until,omitempty"`
	Priority *string `json:"priority,omitempty"`
	Grep     *string `json:"grep,omitempty"`
	Limit    *int    `json:"limit,omitempty"`
}

// journalFollowIn 是 journal_follow 的 MCP 入参(unit 必填)。
type journalFollowIn struct {
	Unit     string  `json:"unit"`
	Since    *string `json:"since,omitempty"`
	Until    *string `json:"until,omitempty"`
	Priority *string `json:"priority,omitempty"`
	Grep     *string `json:"grep,omitempty"`
}

func main() {
	server := newServer(newService())

	// SIGINT/SIGTERM 触发优雅退出;Run 返回后错误信息写 stderr,
	// 以保持 stdout 的 JSON-RPC 数据流完整。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !isCleanShutdown(err) {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}
}

// isCleanShutdown 判定"正常结束":stdin 客户端断开(context.Canceled / EOF)与
// SDK 内部 jsonrpc2.ErrServerClosing("server is closing: ...");后者位于 internal
// 包无法用 errors.Is 匹配,按消息前缀归类。
func isCleanShutdown(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return true
	}
	return strings.HasPrefix(err.Error(), "server is closing")
}

func newServer(svc *service) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	// go-sdk 的 DestructiveHint/OpenWorldHint 为 *bool 且 SDK 未导出取址助手,
	// 按实证形态用局部变量取址(只读 journald 查询必然非破坏性、封闭世界)。
	nonDestructive := false
	closedWorld := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "journal_query",
		Description: "只读结构化查询 journald 日志(journalctl -o json)。\n\n支持按单元、时间窗、优先级、正则与条数过滤;参数在拼 argv 前强制校验。\n\n参数：\n    unit: systemd 单元名(可选)。\n    since/until: 时间窗(可选,如 '-1h'、'2026-01-02 12:00:00')。\n    priority: 0..7 或 emerg..debug(可选)。\n    grep: 消息正则(可选)。\n    limit: 返回条数上限(可选,缺省 100,最大 1000)。\n\n返回：\n    {\"entries\": [...], \"skipped_lines\": N, \"note\": \"...\"}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"unit":     {Type: "string", Description: "systemd 单元名(可选,如 'sshd.service')。"},
				"since":    {Type: "string", Description: "起始时间(可选,如 '-1h' 或 '2026-01-02 12:00:00')。"},
				"until":    {Type: "string", Description: "结束时间(可选,格式同 since)。"},
				"priority": {Type: "string", Description: "优先级 0..7 或 emerg..debug(可选)。"},
				"grep":     {Type: "string", Description: "消息正则过滤(可选)。"},
				"limit":    {Type: "integer", Description: "返回条数上限(可选,缺省 100,最大 1000)。"},
			},
		},
		Annotations: annotations,
	}, handleJournalQuery(svc))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "journal_follow",
		Description: "有界订阅 journald 日志(journalctl --follow -n 0 -o json)。\n\n只跟随调用后产生的新条目(-n 0,不回放历史):journalctl --follow 缺省会先回放最近 10 条再流式,此处显式 -n 0 切到严格 post-invocation 语义。\n\n持续跟随直到 1000 条或 30 秒上限先到,返回已收集批量(非持久订阅);到期无新条目则返回空集 + 上限 note。\n\n参数：\n    unit: systemd 单元名(必填)。\n    since/until/priority/grep: 同 journal_query(可选)。\n\n返回：\n    {\"entries\": [...], \"skipped_lines\": N, \"note\": \"...\"}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"unit":     {Type: "string", Description: "systemd 单元名(必填,如 'sshd.service')。"},
				"since":    {Type: "string", Description: "起始时间(可选,如 '-1h')。"},
				"until":    {Type: "string", Description: "结束时间(可选,格式同 since)。"},
				"priority": {Type: "string", Description: "优先级 0..7 或 emerg..debug(可选)。"},
				"grep":     {Type: "string", Description: "消息正则过滤(可选)。"},
			},
			Required: []string{"unit"},
		},
		Annotations: annotations,
	}, handleJournalFollow(svc))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "journal_last_boot",
		Description: "只读返回上一次启动(-b -1)的最近日志。\n\n固定读取最近 50 条 journalctl -o json 记录。\n\n返回：\n    {\"entries\": [...], \"note\": \"...\"}。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, any, error) {
		return jsonResult(svc.LastBoot(ctx)), nil, nil
	})

	return server
}

// handleJournalQuery 把 MCP 入参转 QueryArgs 后执行;校验/CLI 错误以工具错误
// 结果返回,不 panic。
func handleJournalQuery(svc *service) func(context.Context, *mcp.CallToolRequest, journalQueryIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in journalQueryIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.Query(ctx, QueryArgs{
			Unit:     in.Unit,
			Since:    in.Since,
			Until:    in.Until,
			Priority: in.Priority,
			Grep:     in.Grep,
			Limit:    in.Limit,
		})
		if err != nil {
			return raisedError("journal_query", err), nil, nil
		}
		return jsonResult(res), nil, nil
	}
}

// handleJournalFollow 把 MCP 入参转 FollowArgs 后执行有界订阅。
func handleJournalFollow(svc *service) func(context.Context, *mcp.CallToolRequest, journalFollowIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in journalFollowIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.Follow(ctx, FollowArgs{
			Unit:     in.Unit,
			Since:    in.Since,
			Until:    in.Until,
			Priority: in.Priority,
			Grep:     in.Grep,
		})
		if err != nil {
			return raisedError("journal_follow", err), nil, nil
		}
		return jsonResult(res), nil, nil
	}
}

// jsonResult 对应 Python FastMCP 的 json.dumps(..., ensure_ascii=False,
// indent=2);Go 端用 SetEscapeHTML(false) + SetIndent("  ") 等价实现。
func jsonResult(v any) *mcp.CallToolResult {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return raisedError("jsonResult", err)
	}
	// Encoder.Encode 追加换行,py json.dumps 不带,尾部去除。
	return textResult(strings.TrimSuffix(buf.String(), "\n"))
}

// textResult 构造成功结果(单文本块);家族约定:helper 各服务器各持本地副本。
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// raisedError 构造 isError=true 的工具错误结果,文本形态与 FastMCP 未捕获异常
// 转换一致:"Error executing tool <name>: <消息>"。
func raisedError(tool string, err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error executing tool %s: %v", tool, err)}},
		IsError: true,
	}
}
