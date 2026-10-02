// Command daedalus-avc 是 SELinux AVC 拒绝记录只读 MCP 服务器(stdio JSON-RPC)。
//
// 提供 3 个 L0 工具:avc_recent(近期 AVC/USER_AVC 拒绝列表)、avc_explain
// (单事件原因 + 建议策略解释)、avc_summary(按来源域/目标类/命令/权限聚合)。
// 全部直 fork ausearch / audit2why / audit2allow 三只 CLI,零写入;任意 CLI
// 缺失一律优雅降级为空集 + note,绝不修改 SELinux 策略。
//
// 安全边界:入参在拼 argv 前强制校验,绝对路径 argv 直发不走 sh -c;工具名
// 与 manifest.tools 逐字一致(76 脚本构建期交叉核对,漂移即构建失败)。
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

const serverName = "daedalus-avc"

// emptyIn 是无参工具的输入类型(客户端 arguments 必须是 JSON 对象)。
type emptyIn struct{}

// noArgsSchema 对应无参工具的 {"type": "object"} 输入模式。
var noArgsSchema = &jsonschema.Schema{Type: "object"}

// avcRecentIn 是 avc_recent 的 MCP 入参(since 可选,limit 可选)。
type avcRecentIn struct {
	Since *string `json:"since,omitempty"`
	Limit *int    `json:"limit,omitempty"`
}

// avcExplainIn 是 avc_explain 的 MCP 入参(event_id 必填)。
type avcExplainIn struct {
	EventID string `json:"event_id"`
}

// avcSummaryIn 是 avc_summary 的 MCP 入参(since 可选)。
type avcSummaryIn struct {
	Since *string `json:"since,omitempty"`
}

func main() {
	// 启动期探测三只 CLI 可用性,缺失只提示一次;工具调用各自降级为 note。
	checkStartupEnv()

	server := newServer(newService())

	// SIGINT/SIGTERM 触发优雅退出;Run 返回后错误写 stderr,保持 stdout 的
	// JSON-RPC 数据流完整。
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
	// 按实证形态用局部变量取址(只读查询必然非破坏性、封闭世界)。
	nonDestructive := false
	closedWorld := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true, // 3 工具皆为只读 AVC 查询
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "avc_recent",
		Description: "只读列出近期 SELinux AVC/USER_AVC 拒绝事件(ausearch -m avc,user_avc 解析)。auditd 未启用 / 审计日志不可读 / ausearch 缺失时优雅降级为空集 + note;绝不修改 SELinux 策略。\n\n参数:\n    since: 起始时间(可选;支持 today/yesterday/now/recent/this-week/this-month/this-year/星期名,或 YYYY-MM-DD[ HH:MM:SS] / MM/DD/YYYY[ HH:MM:SS])。\n    limit: 返回条数上限(可选,缺省 200,最大 10000)。\n\n返回:\n    {\"events\": [{\"event_id\": \"...\", \"type\": \"AVC|USER_AVC\", \"scontext\": \"...\", \"tcontext\": \"...\", \"tclass\": \"...\", \"perm\": \"...\", \"comm\": \"...\", \"pid\": \"...\", \"permissive\": bool, \"timestamp\": \"...\"}], \"total_lines\": N, \"returned\": M, \"truncated\": bool, \"note\": \"...\"}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"since": {Type: "string", Description: "起始时间(可选;today/yesterday/now/recent/星期名,或 YYYY-MM-DD[ HH:MM:SS] / MM/DD/YYYY[ HH:MM:SS])。"},
				"limit": {Type: "integer", Description: "返回条数上限(可选,缺省 200,最大 10000)。"},
			},
		},
		Annotations: annotations,
	}, handleAVCRecent(svc))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "avc_explain",
		Description: "只读解释单条 SELinux AVC 拒绝事件:先用 ausearch -a <event_id> 拉原记录,再经 audit2why 解释被拒原因、audit2allow --explain 给出建议 allow 规则。绝不修改 SELinux 策略;event_id 不存在 / CLI 缺失时降级为 note。\n\n参数:\n    event_id: 审计事件序列号(必填;仅数字,或 epoch:serial 形态)。\n\n返回:\n    {\"event_id\": \"...\", \"reason\": \"...\", \"suggestion\": \"...\", \"confidence\": \"type_enforcement|boolean|policy_version|none|unknown\", \"note\": \"...\"}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"event_id": {Type: "string", Description: "审计事件序列号(必填;仅数字,或 epoch:serial 形态)。"},
			},
			Required: []string{"event_id"},
		},
		Annotations: annotations,
	}, handleAVCExplain(svc))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "avc_summary",
		Description: "只读汇总近期 SELinux AVC/USER_AVC 拒绝:按 (scontext|tclass|comm|perm) 分组计数并按 Count 降序返回,附事件总数。ausearch 无 --summary 选项,聚合在服务端完成;降级同 avc_recent,绝不修改 SELinux 策略。\n\n参数:\n    since: 起始时间(可选,语义同 avc_recent)。\n\n返回:\n    {\"total\": N, \"buckets\": [{\"key\": \"scontext|tclass|comm|perm\", \"count\": M}], \"note\": \"...\"}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"since": {Type: "string", Description: "起始时间(可选,语义同 avc_recent)。"},
			},
		},
		Annotations: annotations,
	}, handleAVCSummary(svc))

	return server
}

// handleAVCRecent 把 MCP 入参转 RecentArgs 后执行;校验/CLI 错误以工具错误
// 结果返回,不 panic。
func handleAVCRecent(svc *service) func(context.Context, *mcp.CallToolRequest, avcRecentIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in avcRecentIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.Recent(ctx, RecentArgs{Since: in.Since, Limit: in.Limit})
		if err != nil {
			return raisedError("avc_recent", err), nil, nil
		}
		return jsonResult(res), nil, nil
	}
}

// handleAVCExplain 把 MCP 入参转 ExplainArgs 后执行。
func handleAVCExplain(svc *service) func(context.Context, *mcp.CallToolRequest, avcExplainIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in avcExplainIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.Explain(ctx, ExplainArgs{EventID: in.EventID})
		if err != nil {
			return raisedError("avc_explain", err), nil, nil
		}
		return jsonResult(res), nil, nil
	}
}

// handleAVCSummary 把 MCP 入参转 SummaryArgs 后执行。
func handleAVCSummary(svc *service) func(context.Context, *mcp.CallToolRequest, avcSummaryIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in avcSummaryIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.Summary(ctx, SummaryArgs{Since: in.Since})
		if err != nil {
			return raisedError("avc_summary", err), nil, nil
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
