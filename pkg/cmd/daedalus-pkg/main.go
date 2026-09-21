// Command daedalus-pkg 是软件包能力 MCP 服务器(stdio JSON-RPC,只读)。
//
// 行为规格源:daedalus/files/system/opt/daedalus/servers/pkg_server.py。
// 提供 2 个工具(dnf_query / dnf_list_installed),全部为只读查询;
// 绝不暴露安装/更新/删除等变更操作。
//
// 工具名、参数名(name/pattern)、required 列表、pattern 默认值 "*" 与
// 描述文本均与 py 版逐字一致;命令执行与包名校验逻辑在 internal/pkgquery,
// 错误文案逐字对齐 pkg_server.py:21,23,53,66,68,94,102。
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

	"github.com/Daedalusys/daedalus-sdk/pkgquery"
	"github.com/Daedalusys/daedalus-sdk/version"
)

// serverName 与 pkg_server.py:12 的 FastMCP("daedalus-pkg") 一致。
const serverName = "daedalus-pkg"

// —— 工具输入类型 ——
//
// dnfQueryIn 对应 py:28 的 dnf_query(name: str)(必填)。
type dnfQueryIn struct {
	Name string `json:"name"`
}

// dnfListInstalledIn 对应 py:72 的 dnf_list_installed(pattern: str = "*")。
// Pattern 用 *string 区分"客户端未提供"(nil → 应用默认值 "*")与
// "显式传空串"(必须走 py 的空名拒绝路径),两者语义不可混淆。
type dnfListInstalledIn struct {
	Pattern *string `json:"pattern"`
}

func main() {
	server := newServer(pkgquery.NewService(nil))

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
// SDK 内部 jsonrpc2.ErrServerClosing("server is closing: ...")。
// ErrServerClosing 位于 internal 包无法用 errors.Is 匹配,按消息前缀归类。
func isCleanShutdown(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return true
	}
	return strings.HasPrefix(err.Error(), "server is closing")
}

// newServer 构造并注册全部 2 个工具(测试与 main 共用同一构造入口)。
// 输入 schema 手写而非从 Go 结构体推断,以便逐字复刻 FastMCP 生成的
// 参数描述与 pattern 的 default "*"。
func newServer(svc *pkgquery.Service) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	// go-sdk v1.7.0 的 DestructiveHint 为 *bool 且 SDK 未导出取址助手,
	// 按实证形态用局部变量取址(只读工具必然非破坏性)。
	nonDestructive := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true, // 两工具皆只读查询
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "dnf_query", // 与 py:28 函数名完全一致
		Description: "查询给定软件包名称的软件包信息（只读）。\n\n使用 `rpm -q --info <name>` 查询软件包详细信息，\n如果未在本地安装，则回退到 `dnf repoquery --info <name>`。\n\n参数：\n    name: 要查询的软件包名称（例如 'python3', 'bash'）。\n\n返回：\n    软件包信息字符串或错误消息。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"name": {Type: "string", Description: "要查询的软件包名称（例如 'python3', 'bash'）。"},
			},
			Required: []string{"name"},
		},
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dnfQueryIn) (*mcp.CallToolResult, any, error) {
		out, err := svc.DnfQuery(ctx, in.Name)
		if err != nil {
			// 包名/模式校验失败对应 py:21、py:23 的 ValueError;
			// FastMCP 把未捕获异常转为 isError 结果,Go 侧等价构造。
			return raisedError("dnf_query", err), nil, nil
		}
		// py 版返回 str → FastMCP 原样作为文本内容(不做 JSON 包装)。
		return textResult(out), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "dnf_list_installed", // 与 py:72 函数名完全一致
		Description: "列出匹配模式的已安装软件包（只读）。\n\n使用 `rpm -qa <pattern>` 查询已安装的软件包。\n\n参数：\n    pattern: 用于匹配已安装软件包的模式（默认：'*'）。\n\n返回：\n    匹配的已安装软件包名称/版本列表。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"pattern": {
					Type:        "string",
					Description: "用于匹配已安装软件包的模式（默认：'*'）。",
					Default:     json.RawMessage(`"*"`), // py:72 默认参数 pattern="*"
				},
			},
		},
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dnfListInstalledIn) (*mcp.CallToolResult, any, error) {
		pattern := "*"
		if in.Pattern != nil {
			pattern = *in.Pattern
		}
		lines, err := svc.DnfListInstalled(ctx, pattern)
		if err != nil {
			return raisedError("dnf_list_installed", err), nil, nil
		}
		// py 版返回 list[str] → FastMCP 以 JSON 文本(indent=2)呈现。
		return jsonResult(lines), nil, nil
	})

	return server
}

// textResult 构造成功结果(单文本块,内容原样不 JSON 包装)。
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// jsonResult 对应 Python FastMCP 对非字符串返回值的序列化:
// json.dumps(..., ensure_ascii=False, indent=2)。Go 端用
// SetEscapeHTML(false) + SetIndent(" ", 两空格) 等价实现。
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

// raisedError 对应 py 未捕获 ValueError 经 FastMCP 转换后的工具错误结果:
// isError=true,文本为 "Error executing tool <name>: <异常消息>"。
func raisedError(tool string, err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error executing tool %s: %v", tool, err)}},
		IsError: true,
	}
}
