// Command daedalus-tx-mcp 是受控变更通道的 MCP 服务器(stdio JSON-RPC)。
//
// 本插件是 MCP 侧唯一的写入口:tx_preview 只读地回答"能不能改、会跑哪条 argv",
// tx_apply / tx_rollback 才执行;真正的变更由 core 的 daedalus-tx CLI 事务落地。
// 档位表与危险名单在启动时各读一次 —— 改档位表后必须重启,否则同一进程内规则
// 前后不一致,审计里的 tier 就无法复现。
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

const (
	// serverName 同时是 MCP Implementation.Name 与审计 identity。
	serverName = "daedalus.tx"
	// exitStartupFailure 是启动期配置事故的退出码(与 daedalus-tx CLI 的用法错同码)。
	exitStartupFailure = 2
)

func main() {
	os.Exit(run())
}

// run 返回进程退出码:档位表读坏 ⇒ 2(fail-closed 拒启);服务器异常结束 ⇒ 1。
// 拆出来是为了让测试以子进程方式断言启动期行为。
func run() int {
	cfg, err := loadRuntime(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: 启动失败(档位表 fail-closed): %v\n", serverName, err)
		return exitStartupFailure
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newServer(cfg).Run(ctx, &mcp.StdioTransport{}); err != nil && !isCleanShutdown(err) {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		// 家族统一纪律:非正常结束必须非零退出,宿主据此判定子服务器死亡并重启;
		// 静默退 0 会把启动失败伪装成"干净关闭"。
		return 1
	}
	return 0
}

// isCleanShutdown 判定"正常结束":stdin 客户端断开(context.Canceled / EOF)与
// SDK 内部 jsonrpc2.ErrServerClosing。后者位于 internal 包无法 errors.Is,按前缀归类。
func isCleanShutdown(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return true
	}
	return strings.HasPrefix(err.Error(), "server is closing")
}

// textResult 构造成功结果(单文本块);家族约定:helper 各服务器各持本地副本。
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
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

// raisedError 构造 isError=true 的工具错误结果,文本形态与家族其余服务器一致。
func raisedError(tool string, err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error executing tool %s: %v", tool, err)}},
		IsError: true,
	}
}

// errorResult 把结构化拒绝写成 isError 结果:客户端按 error 字段分支,不靠字符串匹配。
func errorResult(serr *structuredError) *mcp.CallToolResult {
	res := jsonResult(serr)
	res.IsError = true
	return res
}
