// Command daedalus-smart 是磁盘 SMART 健康只读 MCP 服务器(stdio JSON-RPC)。
//
// 提供 4 个 L0 工具:smart_list / smart_health / smart_attributes / smart_test,
// 单源 smartctl(smartmontools)。smart_test 在 L1 本批 deferred,见 smart_test.go。
//
// **smartctl 退出码是位掩码**(health/error bit),非"非零=错误":handleExecError
// 把位掩码翻译成 note,只有真 stderr 才判 fatal,见 smart.go。
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

const serverName = "daedalus-smart"

// smartDiskSchema 是 smart_health / smart_attributes 的入参:disk 必须是
// /dev/sd[a-z]+ | /dev/nvme<d>n<d>(p[0-9]+)? | /dev/vd[a-z]+ | /dev/hd[a-z]+ |
// /dev/xvd[a-z]+ | /dev/mmcblk[0-9]+(p[0-9]+)? 形态的字符串。
var smartDiskSchema = &jsonschema.Schema{
	Type:     "object",
	Required: []string{"disk"},
	Properties: map[string]*jsonschema.Schema{
		"disk": {
			Type:        "string",
			Pattern:     `^/dev/(sd[a-z]+|vd[a-z]+|hd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)(p?[0-9]+)?$`,
			Description: "块设备绝对路径(白名单 sd/vd/hd/xvd/nvme/mmcblk;不接受 ..  / 注入 / 空白)。",
		},
	},
}

// smartTestSchema 是 smart_test 的入参:disk 必选,kind 枚举 short|long(默认 short)。
var smartTestSchema = &jsonschema.Schema{
	Type:     "object",
	Required: []string{"disk"},
	Properties: map[string]*jsonschema.Schema{
		"disk": smartDiskSchema.Properties["disk"],
		"kind": {
			Type:        "string",
			Enum:        []any{"short", "long"},
			Description: "self-test 类别:short(默认;短时,~2 分钟)或 long(多小时;慎用)。",
		},
	},
}

// noArgsSchema 是 smart_list 的无参入参。
var noArgsSchema = &jsonschema.Schema{Type: "object"}

func main() {
	server := newServer(newService())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !isCleanShutdown(err) {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}
}

// isCleanShutdown 判定"正常结束":stdin 客户端断开(context.Canceled / EOF)与
// SDK 内部 jsonrpc2.ErrServerClosing("server is closing: ...")。后者位于 internal
// 包无法用 errors.Is 匹配,按消息前缀归类。
func isCleanShutdown(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return true
	}
	return strings.HasPrefix(err.Error(), "server is closing")
}

// toolAnnotations 标注 4 个工具语义:
//   - smart_list / smart_health / smart_attributes:只读遥测,ReadOnlyHint=true
//   - smart_test:L1 暂不触发,语义非破坏性;为诚实表达"本调用不副作用",也置 true
func toolAnnotations(readOnly bool) *mcp.ToolAnnotations {
	nonDestructive := false
	closedWorld := false
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    readOnly,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}
}

// newServer 注册 4 个工具并返回 *mcp.Server。
func newServer(svc *service) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "smart_list",
		Description: "只读列出本机可被 smartctl 探测的磁盘。数据源 `smartctl --scan`,逐行解析为 `{name, type, info}`(type=smartctl 的 d 类型,sat/scsi/nvme 等)。\n\n参数:无。\n\n返回:\n    {\"disks\": [{\"name\": \"/dev/sda\", \"type\": \"sat\", \"info\": \"...\"}], \"note\": \"...\"}。\n\n可选依赖缺失(smartmontools 未装)→ 空集 + note,不报错。",
		InputSchema: noArgsSchema,
		Annotations: toolAnnotations(true),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ map[string]any) (*mcp.CallToolResult, any, error) {
		res, err := svc.List(ctx)
		if err != nil {
			return raisedError("smart_list", err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "smart_health",
		Description: "只读返回指定磁盘的 SMART 健康状态(`smartctl -H`)。\n\n**返回值语义**:\n    passed: 综合判定(true=磁盘健康)。\n    exit_bitmask: smartctl 退出码原文。smartctl 7.x 退出码是位掩码,不是错误码——位 3 = DISK FAILING(权威健康信号),位 4 = prefail attr 触阈,位 6 = 设备错误日志有记录等。详见 note。\n    note: 位掩码的人话翻译;rc=0 时为空。\n\n参数:\n    disk: 块设备绝对路径,如 /dev/sda 或 /dev/nvme0n1。白名单外被拒。\n\n返回:\n    {\"disk\": \"/dev/sda\", \"passed\": true, \"exit_bitmask\": 0, \"note\": \"\"}。",
		InputSchema: smartDiskSchema,
		Annotations: toolAnnotations(true),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
		in := SmartDiskArgs{}
		if d, ok := args["disk"].(string); ok {
			in.Disk = d
		}
		res, err := svc.Health(ctx, in)
		if err != nil {
			return raisedError("smart_health", err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "smart_attributes",
		Description: "只读返回指定磁盘的 SMART 关键属性(`smartctl -A`)——温度、累计上电小时、坏块计数、pending sector、offline uncorrectable 等;ATA 与 NVMe 都支持(分别走属性表与 Key:Value 解析)。\n\n属性表键(均为 canonical 名,RAW_VALUE):\n    Temperature_Celsius / Power_On_Hours / Reallocated_Sector_Ct / Current_Pending_Sector / Offline_Uncorrectable / Available_Spare(NVMe) / Percentage_Used(NVMe) / Media_And_Data_Integrity_Errors(NVMe) / Error_Information_Log_Entries(NVMe) / Power_Cycles(NVMe) / Unsafe_Shutdowns(NVMe)\n\n参数:\n    disk: 块设备绝对路径,如 /dev/sda 或 /dev/nvme0n1。\n\n返回:\n    {\"disk\": \"/dev/sda\", \"vendor\": \"Samsung based SSDs\", \"attrs\": {\"Temperature_Celsius\": 35, ...}, \"note\": \"\"}。",
		InputSchema: smartDiskSchema,
		Annotations: toolAnnotations(true),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
		in := SmartDiskArgs{}
		if d, ok := args["disk"].(string); ok {
			in.Disk = d
		}
		res, err := svc.Attributes(ctx, in)
		if err != nil {
			return raisedError("smart_attributes", err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "smart_test",
		Description: "SMART 自检状态占位。**L1 本批 deferred**:本工具**不触发任何磁盘 I/O**;返回 `started=false` + 说明 note。\n\n理由:SMART 自检属 L1 操作,需 y/n 确认令牌(daedalus-tx/confirm_token)防误启——daedalus.smart 是只读观测插件,与该安全门冲突,需后续与 L1 通道对接后启用。当前实现只服务调用,所以 LLM 不应误以为磁盘已自检。\n\n参数:\n    disk: 块设备绝对路径。\n    kind: short|long(默认 short)。其它值拒绝。\n\n返回:\n    {\"disk\": \"/dev/sda\", \"kind\": \"short\", \"started\": false, \"note\": \"L1 自检需 y/n 确认令牌,本批未启用;未触发任何磁盘 I/O\"}。",
		InputSchema: smartTestSchema,
		Annotations: toolAnnotations(true),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
		in := SmartTestArgs{}
		if d, ok := args["disk"].(string); ok {
			in.Disk = d
		}
		if k, ok := args["kind"].(string); ok {
			in.Kind = k
		}
		res, err := svc.Test(ctx, in)
		if err != nil {
			return raisedError("smart_test", err), nil, nil
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
	return textResult(strings.TrimSuffix(buf.String(), "\n"))
}

// textResult 构造成功结果(单文本块)。
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// raisedError 构造 isError=true 的工具错误结果,文本形态与 FastMCP 未捕获
// 异常转换一致:"Error executing tool <name>: <消息>"。
func raisedError(tool string, err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error executing tool %s: %v", tool, err)}},
		IsError: true,
	}
}
