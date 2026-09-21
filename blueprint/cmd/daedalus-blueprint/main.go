// Command daedalus-blueprint 是蓝图能力 MCP 服务器(stdio JSON-RPC)。
//
// 提供 6 个工具(blueprint_list / blueprint_inspect / blueprint_render /
// blueprint_apply / blueprint_status / blueprint_remove),把可复用的参数化
// 配置模板(nginx/haproxy/postgres/redis 蓝图)以"渲染预览 → 确认令牌 →
// 事务应用"的安全流程交付。蓝图数据经 //go:embed 编入二进制,渲染走 Go
// text/template,应用经 daedalus-tx 的 blueprint.write 适配器(三段生命周期
// 快照/写/回滚),secret 引用只接受 secret:// 形态(明文 fail-closed 拒绝)。
//
// 协议:go-sdk v1.7.0 自动处理 2024-11-05 与 2025-03-26 双协议版本,
// 无需自定义(与现有 5 能力 server 一致)。安全策略经 policy.LoadOrDefault
// 注入(输出目录白名单、post_check 命令白名单、reload 服务白名单)。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/blueprint"
	"github.com/Daedalusys/daedalus-sdk/policy"
	"github.com/Daedalusys/daedalus-sdk/shellpolicy"
	"github.com/Daedalusys/daedalus-sdk/version"
)

// serverName 与 plan 规格一致。
const serverName = "daedalus-blueprint"

// blueprintIdentity 是审计日志的调用者身份(与 daedalus-tx 的 txIdentity 同源)。
const blueprintIdentity = "daedalus-blueprint"

func main() {
	// 单一事实源:启动时读 shared/policy.toml 并接线(fail-closed)。
	if err := applyPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}

	// 注册表:嵌入数据启动期编译,缺一即 panic(fail-closed)。
	reg, err := newRegistry(blueprint.MustLoad(EmbeddedBlueprints()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}
	app := newApp(reg)
	server := newServer(app)

	// SIGINT/SIGTERM 触发优雅退出;Run 返回后错误信息写 stderr,保持 stdout
	// 的 JSON-RPC 数据流完整(参考 daedalus-pkg/main.go:48-70)。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !isCleanShutdown(err) {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}
}

// app 聚合服务器运行期状态:编译注册表 + plan store。handler 经 newServer
// 注入 app 而非依赖包级全局,测试可构造独立 app。
type app struct {
	reg        *registry
	plans      *planStore
	outputDirs []string // policy.Blueprints.OutputDirs 的运行时镜像
	reloadSvcs []string // policy.Blueprints.ReloadServices 的运行时镜像
	// execCmd 是 apply/remove 触发子进程(post_check / systemctl reload)的注入缝。
	// 默认经 os/exec.CommandContext 直发 argv;测试替换为假实现避免真实系统调用。
	execCmd func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// newApp 从编译注册表构造 app(策略值在 applyPolicy 已注入包级变量,此处
// 同步读取 policy 的 output_dirs / reload_services 作为目录边界与 reload 白名单)。
func newApp(reg *registry) *app {
	// 运行期重新读取策略(applyPolicy 保证已成功加载,这里不会失败)。
	p, err := policy.LoadOrDefault()
	if err != nil {
		// 不应到达:applyPolicy 已拒绝损坏策略。
		panic("blueprint: 策略加载失败(fail-closed): " + err.Error())
	}
	return &app{
		reg:        reg,
		plans:      newPlanStore(),
		outputDirs: p.Blueprints.OutputDirs,
		reloadSvcs: p.Blueprints.ReloadServices,
		execCmd: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			err := cmd.Run()
			return nil, err
		},
	}
}

// applyPolicy 加载策略(缺失回退 Default)并完成三处接线:
//  1. shellpolicy.RegisterBlueprintsPostCheckSource 把 policy.Blueprints.
//     PostCheckCommands 注入 post_check 白名单(todo 9/10 留的钩子,todo 16 消费);
//  2. shellpolicy.WithPolicy(p) 注入主白名单/路径/超时等;
//  3. 失败(fail-closed)拒启。
func applyPolicy() error {
	p, err := policy.LoadOrDefault()
	if err != nil {
		return fmt.Errorf("policy load failed, refusing to start: %w", err)
	}
	// todo 9/10 钩子接线(learnings 记录:因 policy↔shellpolicy 循环依赖,
	// 注册只能放消费方 main,不可放 policy 包 init)。
	shellpolicy.RegisterBlueprintsPostCheckSource(func(pp *policy.Policy) []string {
		return pp.Blueprints.PostCheckCommands
	})
	shellpolicy.WithPolicy(p)
	return nil
}

// isCleanShutdown 判定"正常结束"(与 daedalus-pkg/fs 同款)。
func isCleanShutdown(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return true
	}
	return strings.HasPrefix(err.Error(), "server is closing")
}

// newServer 构造并注册全部 6 个工具(测试与 main 共用同一构造入口)。
func newServer(a *app) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	registerListTool(server, a)
	registerInspectTool(server, a)
	registerRenderTool(server, a)
	registerApplyTool(server, a)
	registerStatusTool(server, a)
	registerRemoveTool(server, a)

	return server
}

// ──── MCP 结果构造助手(与 daedalus-pkg/fs 同款) ────

// textResult 构造成功结果(单文本块)。
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// jsonResult 把 v 序列化为 JSON 文本(indent=2,不转义 HTML,等价 py json.dumps)。
func jsonResult(v any) *mcp.CallToolResult {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError(err)
	}
	return textResult(string(data))
}

// toolError 构造工具错误结果(isError=true,文本 "Error: " + 错误消息)。
func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "Error: " + err.Error()}},
		IsError: true,
	}
}

// toolErrorf 是 toolError 的格式化形态。
func toolErrorf(format string, args ...any) *mcp.CallToolResult {
	return toolError(fmt.Errorf(format, args...))
}
