// Command daedalus-sysinfo 是系统信息能力 MCP 服务器(stdio JSON-RPC,只读)。
//
// 行为规格源:sysinfo_server.py。提供 3 个工具(os_release / hardware_info /
// network_status),全部为只读:仅读取 /etc/os-release、/usr/lib/os-release、
// /proc 下的文本与 statfs,以及执行只读的 `ip ... show` 查询;绝不暴露任何
// 写入/配置操作。
//
// 工具名、无参 schema 与描述文本均与 py 版逐字一致;查询逻辑在
// internal/sysinfo,错误文案逐字对齐 sysinfo_server.py。
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
	"github.com/Daedalusys/daedalus-sdk/sysinfo"
	"github.com/Daedalusys/daedalus-sdk/version"
)

const serverName = "daedalus-sysinfo"

// recordAudit 追加一条哈希链审计条目(只读工具,尽力而为,失败仅留一行
// stderr 警告)。sysinfo 无参数工具不存在验证拒绝路径,且 SDK 把采集故障
// 折叠进返回载荷的 error 键而非错误结果,故成功按 "success" 记录;仅当结果
// 本身 isError(如序列化失败)按 "error"。本插件未接入 policy.toml,不传
// LogPath,由 LogAudit 回退 DefaultLogPath()(与 daedalus-shell 解析链一致)。
func recordAudit(tool string, res *mcp.CallToolResult) {
	outcome := "success"
	args := map[string]any{}
	if res != nil && res.IsError {
		outcome = "error"
		if len(res.Content) > 0 {
			if text, ok := res.Content[0].(*mcp.TextContent); ok {
				args["error"] = shortText(text.Text)
			}
		}
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

// shortText 截取错误文本,防超大载荷灌进哈希链。
func shortText(s string) string {
	const maxRunes = 200
	r := []rune(s)
	if len(r) > maxRunes {
		return string(r[:maxRunes]) + "…"
	}
	return string(r)
}

// emptyIn 是三个无参工具的输入类型(客户端 arguments 必须是 JSON 对象)。
type emptyIn struct{}

// noArgsSchema 对应 FastMCP 对无参工具生成的 {"type": "object"} 输入模式。
var noArgsSchema = &jsonschema.Schema{Type: "object"}

func main() {
	server := newServer(sysinfo.NewService(nil, "", nil))

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

func newServer(svc *sysinfo.Service) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	// go-sdk v1.7.0 的 DestructiveHint 为 *bool 且 SDK 未导出取址助手,
	// 按实证形态用局部变量取址(只读工具必然非破坏性)。
	nonDestructive := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true, // 三工具皆为只读系统信息
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "os_release", // 与 py 函数名完全一致
		Description: "解析并返回操作系统发行版信息（只读）。\n\n读取 /etc/os-release 或 /usr/lib/os-release。\n\n返回：\n    将发行版属性键映射到字符串值的字典。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, any, error) {
		// py 版返回 dict → FastMCP 以 JSON 文本(indent=2)呈现。
		res := jsonResult(svc.OSRelease())
		recordAudit("os_release", res)
		return res, nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "hardware_info", // 与 py 函数名完全一致
		Description: "返回 CPU、内存和磁盘使用信息（只读）。\n\n从 /proc/cpuinfo 读取 CPU 信息，从 /proc/meminfo 读取内存信息，\n并通过 shutil.disk_usage 读取根文件系统磁盘使用情况。\n\n返回：\n    包含 cpu、memory 和 disk 统计信息的字典。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, any, error) {
		res := jsonResult(svc.HardwareInfo())
		recordAudit("hardware_info", res)
		return res, nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "network_status", // 与 py 函数名完全一致
		Description: "返回网络接口和地址状态（只读）。\n\n如果可用，通过 `ip -j addr show` 查询网络信息，\n回退到解析 `/proc/net/dev`。\n\n返回：\n    包含网络接口统计信息和详细信息的字典。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, any, error) {
		res := jsonResult(svc.NetworkStatus(ctx))
		recordAudit("network_status", res)
		return res, nil, nil
	})

	return server
}

// jsonResult 对应 Python FastMCP 的 json.dumps(..., ensure_ascii=False,
// indent=2);Go 端用 SetEscapeHTML(false) + SetIndent("  ") 等价实现。
func jsonResult(v any) *mcp.CallToolResult {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return toolError(err)
	}
	// Encoder.Encode 追加换行,py json.dumps 不带,尾部去除。
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.TrimSuffix(buf.String(), "\n")}},
	}
}

func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
		IsError: true,
	}
}
