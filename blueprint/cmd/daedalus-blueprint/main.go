// Command daedalus-blueprint 是蓝图能力 MCP 服务器(stdio JSON-RPC)。
//
// 提供 6 个工具(blueprint_list / blueprint_inspect / blueprint_render /
// blueprint_apply / blueprint_status / blueprint_remove),把可复用的参数化配置
// 模板以"渲染预览 → 确认令牌 → 事务应用"的安全流程交付。蓝图数据经 //go:embed
// 编入二进制;secret 引用只接受 secret:// 形态(明文 fail-closed 拒绝)。安全
// 策略经 policy.LoadOrDefault 注入(输出目录 / post_check 命令 / reload 服务
// 三张白名单)。
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
	// 的 JSON-RPC 数据流完整(与 daedalus-pkg 同款)。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !isCleanShutdown(err) {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}
}

// app 聚合服务器运行期状态:编译注册表 + plan store。handler 经 newServer 注入
// app 而非依赖包级全局,测试可构造独立 app。
type app struct {
	reg        *registry
	plans      *planStore
	outputDirs []string // policy.Blueprints.OutputDirs 的运行时镜像
	reloadSvcs []string // policy.Blueprints.ReloadServices 的运行时镜像
	// execCmd 是 apply/remove 触发子进程的注入缝;默认经 os/exec.CommandContext
	// 直发 argv,测试替换为假实现避免真实系统调用。
	execCmd func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// newApp 从编译注册表构造 app;output_dirs / reload_services 在此同步读为边界。
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

// applyPolicy 加载策略(缺失回退 Default)并完成接线:
//  1. RegisterBlueprintsPostCheckSource 把 PostCheckCommands 注入 post_check
//     白名单;2. WithPolicy(p) 注入主白名单/路径/超时;3. 失败(fail-closed)拒启。
func applyPolicy() error {
	p, err := policy.LoadOrDefault()
	if err != nil {
		return fmt.Errorf("policy load failed, refusing to start: %w", err)
	}
	// 因 policy↔shellpolicy 循环依赖,注册只能放消费方 main,不可放 policy 包 init。
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

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// jsonResult 把 v 序列化为 JSON 文本(indent=2,不转义 HTML,与 py json.dumps 对齐)。
func jsonResult(v any) *mcp.CallToolResult {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError(err)
	}
	return textResult(string(data))
}

func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "Error: " + err.Error()}},
		IsError: true,
	}
}

func toolErrorf(format string, args ...any) *mcp.CallToolResult {
	return toolError(fmt.Errorf(format, args...))
}
