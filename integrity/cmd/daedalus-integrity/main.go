// Command daedalus-integrity 是 RPM 完整性校验只读 MCP 服务器(stdio JSON-RPC)。
//
// 提供 3 个 L0 工具:rpm_verify(rpm -V 差异解析)、rpm_unchanged(完全一致
// 包列表)、rpm_summary(总体偏离统计),全部直 fork /usr/bin/rpm。零写入;
// rpm 缺失一律优雅降级为空集 + note;部署态在 DynamicUser 下若未授予
// CAP_DAC_READ_SEARCH,部分 root-only 路径会因 EACCES 视为 missing。
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

const serverName = "daedalus-integrity"

// emptyIn 是无参工具(rpm_summary)的输入类型(客户端 arguments 必须是 JSON
// 对象)。
type emptyIn struct{}

// noArgsSchema 对应无参工具的 {"type": "object"} 输入模式。
var noArgsSchema = &jsonschema.Schema{Type: "object"}

// rpmVerifyIn 是 rpm_verify 的 MCP 入参(package 与 all 互斥,可选 limit/offset)。
type rpmVerifyIn struct {
	Package *string `json:"package,omitempty"`
	All     bool    `json:"all,omitempty"`
	Limit   *int    `json:"limit,omitempty"`
	Offset  *int    `json:"offset,omitempty"`
}

// rpmUnchangedIn 是 rpm_unchanged 的 MCP 入参(package 可选,可选 limit/offset)。
type rpmUnchangedIn struct {
	Package *string `json:"package,omitempty"`
	Limit   *int    `json:"limit,omitempty"`
	Offset  *int    `json:"offset,omitempty"`
}

func main() {
	// 启动期环境探测:rpm 二进制可用性 + euid,缺失/非 root 往 stderr 提示
	// 一次性,工具调用时各自降级为 note(不崩)。
	checkStartupEnv()

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
	// 按实证形态用局部变量取址(只读校验必然非破坏性、封闭世界)。
	nonDestructive := false
	closedWorld := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true, // 3 工具皆为只读 rpm 查询/校验
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "rpm_verify",
		Description: "只读对比已安装文件与 rpm DB 记录,报告被改的文件(权限/属主/哈希/md5/大小/设备/mtime/symlink/capabilities 偏离)。部署态经 CAP_DAC_READ_SEARCH 可读 root-only 文件做完整性校验(非 root,不获全部特权)。\n\n参数:\n    package: 包名(可选,与 all 互斥;仅字母/数字/下划线/点/@/+/-)。\n    all: 全量校验所有已安装包(可选,与 package 互斥)。\n    limit: 返回条数上限(可选,缺省 1000,最大 10000)。\n    offset: 跳过前 N 条(可选,缺省 0)。\n\n返回:\n    {\"entries\": [{\"package\": \"...\", \"path\": \"...\", \"type\": \"c|d|l|r|g\", \"flags\": {...}}],\n     \"total_lines\": N, \"returned\": M, \"truncated\": bool, \"note\": \"...\"}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"package": {Type: "string", Description: "包名(可选,与 all 互斥)。"},
				"all":     {Type: "boolean", Description: "全量校验所有已安装包(可选,与 package 互斥)。"},
				"limit":   {Type: "integer", Description: "返回条数上限(可选,缺省 1000,最大 10000)。"},
				"offset":  {Type: "integer", Description: "跳过前 N 条(可选,缺省 0)。"},
			},
		},
		Annotations: annotations,
	}, handleRPMVerify(svc))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "rpm_unchanged",
		Description: "只读返回与 rpm DB 完全一致的包列表(绝大多数包应命中)。部署态经 CAP_DAC_READ_SEARCH 可读 root-only 文件做完整性校验(非 root,不获全部特权)。\n\n参数:\n    package: 包名(可选,只检查该包;仅字母/数字/下划线/点/@/+/-)。\n    limit/offset: 分页(可选,同 rpm_verify)。\n\n返回:\n    {\"packages\": [\"bash\", ...], \"total_lines\": N, \"returned\": M, \"truncated\": bool, \"note\": \"...\"}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"package": {Type: "string", Description: "包名(可选,只检查该包)。"},
				"limit":   {Type: "integer", Description: "返回条数上限(可选,缺省 1000,最大 10000)。"},
				"offset":  {Type: "integer", Description: "跳过前 N 条(可选,缺省 0)。"},
			},
		},
		Annotations: annotations,
	}, handleRPMUnchanged(svc))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "rpm_summary",
		Description: "只读返回总体偏离统计:总包数、被改包数、被改文件数,以及被改包名前 50 个示例。部署态经 CAP_DAC_READ_SEARCH 可读 root-only 文件做完整性校验(非 root,不获全部特权)。\n\n返回:\n    {\"total_packages\": N, \"changed_packages\": M, \"changed_files\": K, \"changed_packages_top\": [...], \"changed_packages_more\": P, \"note\": \"...\"}。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.Summary(ctx)
		if err != nil {
			return raisedError("rpm_summary", err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	return server
}

// handleRPMVerify 把 MCP 入参转 VerifyArgs 后执行;校验/CLI 错误以工具错误
// 结果返回,不 panic。
func handleRPMVerify(svc *service) func(context.Context, *mcp.CallToolRequest, rpmVerifyIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in rpmVerifyIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.Verify(ctx, VerifyArgs{
			Package: in.Package,
			All:     in.All,
			Limit:   in.Limit,
			Offset:  in.Offset,
		})
		if err != nil {
			return raisedError("rpm_verify", err), nil, nil
		}
		return jsonResult(res), nil, nil
	}
}

// handleRPMUnchanged 把 MCP 入参转 UnchangedArgs 后执行。
func handleRPMUnchanged(svc *service) func(context.Context, *mcp.CallToolRequest, rpmUnchangedIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in rpmUnchangedIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.Unchanged(ctx, UnchangedArgs{
			Package: in.Package,
			Limit:   in.Limit,
			Offset:  in.Offset,
		})
		if err != nil {
			return raisedError("rpm_unchanged", err), nil, nil
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
