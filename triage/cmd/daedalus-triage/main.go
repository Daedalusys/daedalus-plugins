// Command daedalus-triage 是启动/崩溃排查能力 MCP 服务器(stdio JSON-RPC)。
//
// 提供 5 个 L0 工具:启动耗时分布(boot_blame)、启动关键链
// (boot_critical_chain)、上次启动日志(last_boot_log)、内核转储清单
// (coredumps_list)、单条转储详情(coredump_info)。全部直 fork
// systemd-analyze / coredumpctl / journalctl,零写入;缺二进制一律优雅
// 降级为空集 + note。
//
// 安全边界:全部入参在拼 argv 前强制校验(见 triage.go),再经绝对路径
// argv 直发,绝不经过 sh -c。工具名与 manifest.tools 逐字一致(76 脚本构建期
// 交叉核对 manifest ↔ 二进制 tools/list,漂移即构建失败)。
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

const serverName = "daedalus-triage"

// emptyIn 是无参工具的输入类型(客户端 arguments 必须是 JSON 对象)。
type emptyIn struct{}

// noArgsSchema 对应无参工具的 {"type": "object"} 输入模式。
var noArgsSchema = &jsonschema.Schema{Type: "object"}

// criticalChainIn 是 boot_critical_chain 的 MCP 入参(unit 可选)。
type criticalChainIn struct {
	Unit string `json:"unit,omitempty"`
}

// lastBootLogIn 是 last_boot_log 的 MCP 入参(priority 可选)。
type lastBootLogIn struct {
	Priority *string `json:"priority,omitempty"`
}

// coredumpInfoIn 是 coredump_info 的 MCP 入参(coredump_id 必填)。
type coredumpInfoIn struct {
	CoredumpID string `json:"coredump_id"`
}

func main() {
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

	// 全工具只读、幂等、封闭世界;与 journal 插件注解模板一致。
	nonDestructive := false
	closedWorld := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "boot_blame",
		Description: "只读列出本次启动各单元耗时(systemd 长进度降级与责任分布)。\n\n直 fork `systemd-analyze blame`,解析 `<time>s <unit>` 行;最多保留前 50 条,缺 systemd-analyze 降级为空集 + note。\n\n参数：无。\n\n返回：\n    {\"entries\": [{\"unit\",\"time\",\"seconds\"}], \"note\": \"...\"}。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, any, error) {
		return jsonResult(svc.BootBlame(ctx)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "boot_critical_chain",
		Description: "只读输出启动关键链(systemd 单元依赖树的启动时序)。\n\n直 fork `systemd-analyze critical-chain [unit]`,解析树形输出:每条 `{unit, depth, activation, elapsed}`。unit 可选,空则输出默认目标链。\n\n参数：\n    unit: systemd 单元名(可选,如 'multi-user.target');空则输出默认目标链。\n\n返回：\n    {\"unit\":\"...\", \"tree\":[...], \"note\":\"...\"}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"unit": {Type: "string", Description: "systemd 单元名(可选,如 'multi-user.target')。"},
			},
		},
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in criticalChainIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.BootCriticalChain(ctx, CriticalChainArgs{Unit: in.Unit})
		if err != nil {
			return raisedError("boot_critical_chain", err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "last_boot_log",
		Description: "只读返回上一次启动(-b -1)的最近日志。\n\n直 fork `journalctl -b -1 -n 50 -o json`,可选按 priority 过滤。\n\n参数：\n    priority: 字符串,emerg/alert/crit/err/warning/notice/info/debug 或 0..7(可选)。\n\n返回：\n    {\"entries\": [{\"timestamp\",\"priority\",\"unit\",\"message\"}], \"note\": \"...\"}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"priority": {Type: "string", Description: "字符串:emerg/alert/crit/err/warning/notice/info/debug 或 0..7(可选)。"},
			},
		},
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in lastBootLogIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.LastBootLog(ctx, LastBootLogArgs{Priority: in.Priority})
		if err != nil {
			return raisedError("last_boot_log", err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "coredumps_list",
		Description: "只读列出系统内核转储记录(coredumpctl list)。\n\n直 fork `coredumpctl list --json=short --no-pager`,按 RFC3339Nano 时间、uuid/uid/gid、信号、coredump 文件状态(present/inaccessible)、可执行路径、字节大小排序。无权限的转储(corefile=inaccessible)仍会出现仅 size 为 null。无转储记录返回空集 + note '无内核转储记录'。\n\n参数：无。\n\n返回：\n    {\"entries\": [{\"time\",\"pid\",\"uid\",\"gid\",\"signal\",\"coredump_file\",\"exe\",\"size_bytes\"}], \"note\": \"...\"}。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, any, error) {
		return jsonResult(svc.CoredumpsList(ctx)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "coredump_info",
		Description: "只读读取单条内核转储详情(coredumpctl info <pid>)。\n\n直 fork `coredumpctl info <coredump_id>`,按 'Key: Value' 行解析为扁平 map,同时保留 raw 原文(含 stack trace),超过 64KiB 截断。无匹配返回空字段 + note '无内核转储记录'。\n\n参数：\n    coredump_id: 字符串,仅限正整数 PID(必填);不接受进程名、可执行路径、@时间戳等 coredumpctl 其他匹配式。\n\n返回：\n    {\"coredump_id\":\"...\", \"fields\":{\"PID\":\"...\"}, \"raw\":\"...\", \"note\": \"...\"}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"coredump_id": {Type: "string", Description: "正整数 PID(必填);不接受进程名、路径、@时间戳等。"},
			},
			Required: []string{"coredump_id"},
		},
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in coredumpInfoIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.CoredumpInfo(ctx, in.CoredumpID)
		if err != nil {
			return raisedError("coredump_info", err), nil, nil
		}
		return jsonResult(res), nil, nil
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
