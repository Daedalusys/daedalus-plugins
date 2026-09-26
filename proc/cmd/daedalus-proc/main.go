// Command daedalus-proc 是进程侦察 MCP 服务器(stdio JSON-RPC,只读)。
//
// 直读 /proc 提供 5 个 L0 工具:proc_list(进程列表)/ proc_tree(进程树)/
// proc_fds(打开的文件描述符)/ proc_listen(监听端口反查进程)/ proc_cgroup
// (所属 systemd 单元)。与 002 ops 互补:ops 走 systemctl 管理单元,本服务器
// 走 /proc 内省,不触碰任何控制面。
//
// 安全边界:零 exec、零写入、无 kill/signal/renice(L2 变更走 daedalus-tx);
// pid 一律正整数校验后 strconv.Itoa 拼接,字符串参数只做包含比较。
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

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const serverName = "daedalus-proc"

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
