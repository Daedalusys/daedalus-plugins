// Command daedalus-pkg 是软件包能力 MCP 服务器(stdio JSON-RPC,只读)。
//
// 行为规格源:pkg_server.py。提供 2 个工具(dnf_query / dnf_list_installed),
// 全部为只读查询,绝不暴露安装/更新/删除等变更操作。
//
// 工具名、参数名(name/pattern)、required 列表、pattern 默认值 "*" 与描述文本
// 均与 py 版逐字一致;命令执行与包名校验逻辑在 internal/pkgquery,错误文案逐字对齐
// pkg_server.py。
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

	"github.com/Daedalusys/daedalus-sdk/audit"
	"github.com/Daedalusys/daedalus-sdk/pkgquery"
	"github.com/Daedalusys/daedalus-sdk/version"
)

const serverName = "daedalus-pkg"

// recordAudit 追加一条哈希链审计条目(只读工具,尽力而为)。本插件未接入
// policy.toml,故不传 LogPath,由 LogAudit 回退 DefaultLogPath()
// (DAEDALUS_AUDIT_LOG_PATH 环境变量 > /var/log/daedalus/audit.jsonl),
// 与 daedalus-shell 的解析链一致。失败只留一行 stderr 警告。
func recordAudit(tool, outcome string, args map[string]any, cause error) {
	if cause != nil {
		args["error"] = shortErrText(cause)
	}
	var v *audit.Value
	data, err := json.Marshal(args)
	if err == nil {
		v, err = audit.ParseValue(string(data))
	}
	if err == nil {
		_, err = audit.LogAudit(audit.Entry{
			Identity: serverName,
			Tool:     tool,
			Args:     v,
			Outcome:  outcome,
		})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: 审计写入失败: %v\n", serverName, err)
	}
}

// classifyPkgError 区分 denied 与 error:pkgquery 对包名/模式的两条校验文案
// 属验证拒绝,其余(rpm/dnf 无法启动等)属处理器内部故障。文案为 SDK 固定串。
func classifyPkgError(err error) string {
	msg := err.Error()
	if strings.HasPrefix(msg, "Package name/pattern cannot be empty.") ||
		strings.HasPrefix(msg, "Invalid package name or pattern:") {
		return "denied"
	}
	return "error"
}

// shortErrText 截取错误消息,防超长命令输出灌进哈希载荷。
func shortErrText(err error) string {
	const maxRunes = 200
	r := []rune(err.Error())
	if len(r) > maxRunes {
		return string(r[:maxRunes]) + "…"
	}
	return string(r)
}

// dnfQueryIn 对应 py 的 dnf_query(name: str)(必填)。
type dnfQueryIn struct {
	Name string `json:"name"`
}

// dnfListInstalledIn 对应 py 的 dnf_list_installed(pattern: str = "*")。
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

// newServer 构造并注册全部 2 个工具。输入 schema 手写而非从 Go 结构体推断,
// 以便逐字复刻 FastMCP 生成的参数描述与 pattern 的 default "*"。
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
		Name:        "dnf_query", // 与 py 函数名完全一致
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
			// 校验失败对应 py 的 ValueError;FastMCP 把未捕获异常转为 isError 结果。
			recordAudit("dnf_query", classifyPkgError(err), map[string]any{"name": in.Name}, err)
			return raisedError("dnf_query", err), nil, nil
		}
		recordAudit("dnf_query", "success", map[string]any{"name": in.Name}, nil)
		// py 版返回 str → FastMCP 原样作为文本内容(不做 JSON 包装)。
		return textResult(out), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "dnf_list_installed", // 与 py 函数名完全一致
		Description: "列出匹配模式的已安装软件包（只读）。\n\n使用 `rpm -qa <pattern>` 查询已安装的软件包。\n\n参数：\n    pattern: 用于匹配已安装软件包的模式（默认：'*'）。\n\n返回：\n    匹配的已安装软件包名称/版本列表。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"pattern": {
					Type:        "string",
					Description: "用于匹配已安装软件包的模式（默认：'*'）。",
					Default:     json.RawMessage(`"*"`), // py 默认参数 pattern="*"
				},
			},
		},
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dnfListInstalledIn) (*mcp.CallToolResult, any, error) {
		pattern := "*"
		if in.Pattern != nil {
			pattern = *in.Pattern
		}
		args := map[string]any{"pattern": pattern}
		lines, err := svc.DnfListInstalled(ctx, pattern)
		if err != nil {
			recordAudit("dnf_list_installed", classifyPkgError(err), args, err)
			return raisedError("dnf_list_installed", err), nil, nil
		}
		recordAudit("dnf_list_installed", "success", args, nil)
		// py 版返回 list[str] → FastMCP 以 JSON 文本(indent=2)呈现。
		return jsonResult(lines), nil, nil
	})

	return server
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
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

// raisedError 对应 py 未捕获 ValueError 经 FastMCP 转换后的工具错误结果:
// isError=true,文本为 "Error executing tool <name>: <异常消息>"。
func raisedError(tool string, err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error executing tool %s: %v", tool, err)}},
		IsError: true,
	}
}
