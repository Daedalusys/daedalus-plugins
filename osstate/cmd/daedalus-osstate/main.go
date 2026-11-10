// Command daedalus-osstate 是操作系统状态能力 MCP 服务器(stdio JSON-RPC,只读)。
//
// 提供 2 个工具(os_state / filesystem_info):读取 os-release 文本与
// /proc/self/mountinfo 文本,并按固定绝对路径候选表 stat 探测包管理器与 init。
// 零 exec、零写入:不建、不改、不删任何文件,也不改变系统状态。
//
// 探测走固定绝对路径候选表而非 PATH 搜索:宿主 PATH 不可控,且每条候选路径
// 都要能在 manifest 的 permissions 里逐条声明,才能被宿主沙箱如实授权。
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

const serverName = "daedalus-osstate"

// newSysinfoService 构造发行版采集器;root 生产恒为 "/",测试重定向到临时目录,
// 保证单测永不读宿主 /etc。
var newSysinfoService = func(root string) *sysinfo.Service {
	return sysinfo.NewService(nil, root, nil)
}

// pathExists 只做存在性探测:不打开、不执行。放包级变量是为了让测试用内存集合
// 替换它(快照插件同款),而不是去 mock 整棵宿主文件树。
var pathExists = func(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// recordAudit 追加一条哈希链审计条目(只读工具,尽力而为,失败仅留一行
// stderr 警告)。采集故障折叠进回包的 error 键而非错误结果,故成功按
// "success" 记录;仅当结果本身 isError(如序列化失败)按 "error"。
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

// emptyIn 是无参工具的输入类型(客户端 arguments 必须是 JSON 对象)。
type emptyIn struct{}

// noArgsSchema 对应 FastMCP 对无参工具生成的 {"type": "object"} 输入模式。
var noArgsSchema = &jsonschema.Schema{Type: "object"}

func main() {
	server := newServer()

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

func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	// go-sdk 的 DestructiveHint/OpenWorldHint 为 *bool 且 SDK 未导出取址助手,
	// 按实证形态用局部变量取址(只读工具必然非破坏性、封闭世界)。
	nonDestructive := false
	closedWorld := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name: "os_state",
		Description: "返回操作系统身份事实（只读）。\n\n" +
			"读取 /etc/os-release 或 /usr/lib/os-release 得到发行版 id/版本/pretty name；\n" +
			"并按固定绝对路径候选表 stat 探测包管理器（apt/dnf/yum/zypper/apk）与 init。\n\n" +
			"返回：\n" +
			"    形如 {\"distro\":{...},\"package_manager\":{...},\"init\":\"systemd\"} 的对象；\n" +
			"    发行版读不到时只返回 {\"error\": ...}。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, any, error) {
		res := jsonResult(osStatePayload(newSysinfoService("/").OSRelease()))
		recordAudit("os_state", res)
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
