// Command daedalus-service 是 Service 观测能力 MCP 服务器(stdio JSON-RPC,只读)。
//
// 计划 todo 5 骨架 + todo 6 service.query + todo 7 service.list:类型化
// systemd 单元观测(属性查询 + 服务列表),返回 internal/objectmodel 的
// ServiceState 载荷(kind/name/desired_state/properties)。service.list 的
// 处理器与解析住在同包 list.go(250 纯 LOC 上限下的包内拆分);本文件
// 不引入 applyPolicy、任何变更操作或第二策略事实源。
//
// 清单交叉引用:本插件 manifest 的 resources 声明("kind": "service")与
// 本服务器返回的载荷类型,其 schema 单一事实源均在
// daedalus/core/internal/objectmodel/objectmodel.go;事务与执行模型见计划
// .omo/plans/aios-object-model-alignment.md 的 Object Model 段与决策 25
// (JSON 清单不能携带注释,故引用住本文件头)。
//
// 安全边界:单元名/过滤模式先经白名单正则 + 遍历检查(argv 构造前拒绝),
// 再经 os/exec **argv 直发**执行 systemctl(绝不经过 sh -c);属性查询
// 限定 curated 只读白名单。
//
// 结构镜像 cmd/daedalus-pkg/main.go(main + isCleanShutdown 逐字同型,
// textResult/jsonResult/raisedError 按家族约定各服务器各自持有本地副本);
// 协议协商由 go-sdk v1.7.0 默认处理:同时接受 2024-11-05(copilot exec.ts
// 握手)与 2025-03-26(76 脚本 binary_tools)客户端,不加任何自定义版本逻辑。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/objectmodel"
	"github.com/Daedalusys/daedalus-sdk/version"
)

// serverName 为 MCP 服务器标识,与插件 id "daedalus.service" 的短名对应。
const serverName = "daedalus-service"

// systemctlBinary 是 systemctl 的绝对路径。包级变量而非常量的唯一理由:
// 测试注入 t.TempDir() 下的 KEY=VALUE 夹具,永不触碰宿主真实 systemd。
// 生产态固定为镜像内的 /usr/bin/systemctl(argv 直发,无 $PATH 查找)。
var systemctlBinary = "/usr/bin/systemctl"

// systemctlTimeout 为单次 systemctl 调用的兜底超时(30s)。取值与镜像
// policy.toml [shell].timeout_ms 缺省一致;本服务不加载 policy.toml
// (仅只读查询,无策略面),故以编译期常量钉死,改动无需运行时配置。
const systemctlTimeout = 30 * time.Second

// queryProperties 是 service.query 的 curated 只读属性白名单(计划 todo 6
// 逐字 pin 的 7 项)。systemctl show 对未知单元也会回 LoadState=not-found,
// 因此"单元不存在"经 LoadState 判定而非退出码。
var queryProperties = []string{
	"ActiveState",
	"SubState",
	"MainPID",
	"LoadState",
	"UnitFileState",
	"ActiveEnterTimestamp",
	"FragmentPath",
}

// unitNamePattern 是单元名白名单正则:仅字母/数字/下划线/点/@/-。
// 天然排除路径分隔符、shell 元字符、空白与注入语法;".." 遍历序列
// 虽能通过字符类,由 normalizeUnitName 的显式检查兜底。
var unitNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]+$`)

// serviceQueryIn 对应 service.query(name: str)(必填)。
type serviceQueryIn struct {
	Name string `json:"name"`
}

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

// newServer 构造 MCP 服务器实例并注册已落位工具(测试与 main 共用同一
// 构造入口)。todo 6: service.query;todo 7: service.list。
func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	// go-sdk v1.7.0 的 DestructiveHint/OpenWorldHint 为 *bool 且 SDK 未导出
	// 取址助手,按实证形态用局部变量取址(只读查询必然非破坏性、封闭世界)。
	nonDestructive := false
	closedWorld := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "service.query",
		Description: "只读查询 systemd 单元属性。\n\n通过 `systemctl show <name>.service` 读取固定白名单内的\n单元属性(ActiveState/SubState/MainPID/LoadState/UnitFileState/\nActiveEnterTimestamp/FragmentPath)。\n\n参数：\n    name: 单元名,省略 .service 后缀时自动补全(例如 'sshd')。\n\n返回：\n    Service 资源的类型化状态对象(kind/name/desired_state/properties)。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"name": {Type: "string", Description: "要查询的 systemd 单元名,省略 .service 后缀时自动补全(例如 'sshd')。"},
			},
			Required: []string{"name"},
		},
		Annotations: annotations,
	}, handleServiceQuery)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "service.list",
		Description: "只读列出 systemd 服务单元。\n\n通过 `systemctl list-units --type=service --all --no-pager --no-legend [filter]`\n列出全部(含未激活)服务,逐行解析 UNIT/LOAD/ACTIVE/SUB 四列。\n\n参数：\n    filter: 单元名匹配模式,仅接受单元名字符集或通配 '*'（默认：'*' 列出全部）。\n\n返回：\n    按单元名升序排列的 Service 状态对象数组(kind/name/desired_state/properties)。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"filter": {
					Type:        "string",
					Description: "单元名匹配模式,仅接受字母/数字/下划线/点/@/- 组成的单元名或其子串（默认：'*' 列出全部）。",
					Default:     json.RawMessage(`"*"`), // 缺省参数 filter="*",镜像 pkg dnf_list_installed 形态
				},
			},
		},
		Annotations: annotations,
	}, handleServiceList)

	return server
}

// handleServiceQuery 是 service.query 的处理器:名字校验(argv 构造前
// fail-closed)→ systemctl show 直发 → LoadState 判缺 → ServiceState
// JSON 载荷。校验/执行失败经 raisedError 呈现为 isError 工具结果。
func handleServiceQuery(ctx context.Context, _ *mcp.CallToolRequest, in serviceQueryIn) (*mcp.CallToolResult, any, error) {
	const toolName = "service.query"

	unit, err := normalizeUnitName(in.Name)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	props, err := runSystemctlShow(ctx, unit)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	// 计划 pin:not-found 与 masked 两种 LoadState 皆以逐字文案拒绝。
	if ls := props["LoadState"]; ls == "not-found" || ls == "masked" {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error: unit %s not found", unit)}},
			IsError: true,
		}, nil, nil
	}
	result := objectmodel.ServiceState{
		Kind:         string(objectmodel.KindService),
		Name:         unit,
		DesiredState: "", // 观测态无期望(查询路径恒空,计划 pin)
		Properties:   props,
	}
	// todo 20:成功观测 → state 记忆一条(Name=单元名,载荷=回包同一份
	// JSON);best-effort,失败只落 stderr,不影响下面的工具返回值。
	recordServiceState(unit, result)
	return jsonResult(result), nil, nil
}

// normalizeUnitName 校验单元名并补全隐式 .service 后缀。拒绝路径:
//  1. 空串;
//  2. 不匹配白名单正则(排除 '/'、'\'、shell 元字符、空白、非 ASCII);
//  3. 补后缀后含 ".." 遍历序列(字符类放行点号,此检查覆盖 ".."、
//     尾点拼接出的 "x..service" 等形态)。
//
// 一切拒绝都发生在拼 argv 之前——非法名永不抵达 exec。
func normalizeUnitName(name string) (string, error) {
	if name == "" {
		return "", errors.New("name 不能为空")
	}
	if !unitNamePattern.MatchString(name) {
		return "", fmt.Errorf("非法单元名: %q", name)
	}
	if !strings.HasSuffix(name, ".service") {
		name += ".service"
	}
	if strings.Contains(name, "..") {
		return "", fmt.Errorf("非法单元名(路径遍历): %q", name)
	}
	return name, nil
}

// runSystemctlShow argv 直发执行 `systemctl show <unit> --property=...`
// (逐项重复 --property,systemctl 官方支持形态;绝不经过 sh -c)。
// 输出按 KEY=VALUE 逐行解析,键为 systemctl 属性名原文。
func runSystemctlShow(ctx context.Context, unit string) (map[string]string, error) {
	execCtx, cancel := context.WithTimeout(ctx, systemctlTimeout)
	defer cancel()

	args := make([]string, 0, 1+len(queryProperties)+1)
	args = append(args, "show", unit)
	for _, p := range queryProperties {
		args = append(args, "--property="+p)
	}

	cmd := exec.CommandContext(execCtx, systemctlBinary, args...)
	// stdin 置空(→ /dev/null):服务器 stdin 是 JSON-RPC 帧流,
	// 子进程若继承管道会吞掉未读的协议数据。
	cmd.Stdin = nil
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("systemctl show 失败: %w(%s)", err, strings.TrimSpace(stderr.String()))
	}
	return parseKeyValueLines(stdout.String()), nil
}

// parseKeyValueLines 解析 systemctl show 的 KEY=VALUE 输出:按首个 '='
// 切分,空值合法(如 ActiveEnterTimestamp=),无 '=' 的行静默跳过。
func parseKeyValueLines(out string) map[string]string {
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		props[key] = value
	}
	return props
}

// textResult 构造成功结果(单文本块,内容原样不 JSON 包装)。
// 家族约定:各能力服务器各自持有本组 helper 的本地副本。
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

// raisedError 构造 isError=true 的工具错误结果,文本形态与
// FastMCP 未捕获异常转换一致:"Error executing tool <name>: <消息>"。
func raisedError(tool string, err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error executing tool %s: %v", tool, err)}},
		IsError: true,
	}
}
