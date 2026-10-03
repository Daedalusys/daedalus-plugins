// Command daedalus-gpu 是 GPU 遥测只读 MCP 服务器(stdio JSON-RPC)。
//
// 提供 4 个 L0 工具:gpu_list / gpu_status / gpu_processes / gpu_memory,并联
// NVIDIA(nvidia-smi)/ AMD(rocm-smi)/ Intel(intel_gpu_top)三厂商 CLI;零写入。
//
// **可选依赖**:每厂商启动期与调用期双重 exec.LookPath 探测,缺即"跳过该厂商"
// 而非报错;三厂商全缺返回空集 + note。工具名与 manifest.tools 逐字一致
// (76 脚本构建期交叉核对,漂移即构建失败)。
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

const serverName = "daedalus-gpu"

// emptyIn 是 gpu_list 的无参入参。
type emptyIn struct{}

// gpuSelectIn 是 gpu_status/gpu_processes/gpu_memory 的可选 GPU 索引入参。
type gpuSelectIn struct {
	GPU *int `json:"gpu,omitempty"`
}

// noArgsSchema 对应无参工具的 {"type": "object"} 输入模式。
var noArgsSchema = &jsonschema.Schema{Type: "object"}

// gpuSelectSchema 是可选 gpu 索引的输入模式。
var gpuSelectSchema = &jsonschema.Schema{
	Type: "object",
	Properties: map[string]*jsonschema.Schema{
		"gpu": {
			Type:        "integer",
			Description: "GPU 全局序号(可选;省略 = 全部 GPU)。必须是 gpu_list 返回的某个 index;越界返回工具错误。",
		},
	},
}

func main() {
	server := newServer(newService())

	// SIGINT/SIGTERM 触发优雅退出;Run 返回后错误写 stderr,保持 stdout 的
	// JSON-RPC 数据流完整。
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

	// go-sdk 的 DestructiveHint/OpenWorldHint 为 *bool 且 SDK 未导出取址助手,
	// 按实证形态用局部变量取址(只读遥测必然非破坏性、封闭世界)。
	nonDestructive := false
	closedWorld := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "gpu_list",
		Description: "只读列出本机 GPU(厂商/型号/驱动版本)。数据源按 NVIDIA(nvidia-smi)/ AMD(rocm-smi)/ Intel(intel_gpu_top)顺序探测;可选依赖缺失的厂商跳过,全缺失返回空集 + note,不报错。\n\n参数:无。\n\n返回:\n    {\"gpus\": [{\"index\": 0, \"vendor\": \"nvidia|amd|intel\", \"name\": \"...\", \"driver\": \"...\", \"temperature\": null, \"utilization\": null, \"memory_total\": null, \"memory_used\": null, \"memory_free\": null, \"power\": null}], \"note\": \"...\"}。\n\n**同名异义**字段(temperature/utilization/memory_*/power)在 gpu_list 一律返回 null,语义差异见 gpu_status。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.List(ctx)
		if err != nil {
			return raisedError("gpu_list", err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "gpu_status",
		Description: "只读返回 GPU 利用率/显存/温度/功耗(默认全部 GPU)。\n\n**同名异义(跨厂商语义不同,请按 vendor 字段区分)**:\n    utilization: NVIDIA = SM%(流式多处理器占用);AMD = GFX%(图形管线繁忙度);Intel = Render/3D 引擎 busy%(Blitter/Video/VideoEnhance 另行统计)。\n    temperature: NVIDIA = 核心温度(°C);AMD = Sensor edge(边缘结温,junction/memory 另行报);Intel = 未暴露 → null。\n    memory_total/memory_used/memory_free: 单位 MiB;AMD 原生是字节(B)已换算;Intel = 未暴露 → null。\n    power: 单位 W;NVIDIA = power.draw(采样点瞬时);AMD = Average Graphics Package Power(采样均值);Intel = 未暴露 → null。\n\n参数:\n    gpu: GPU 全局序号(可选;省略 = 全部;越界报工具错误)。\n\n返回:\n    {\"gpus\": [{\"index\": 0, \"vendor\": \"...\", \"name\": \"...\", \"driver\": \"...\", \"temperature\": 45.0, \"utilization\": 12.3, \"memory_total\": 24564.0, \"memory_used\": 1234.0, \"memory_free\": 23330.0, \"power\": 65.32}], \"note\": \"...\"}。",
		InputSchema: gpuSelectSchema,
		Annotations: annotations,
	}, handleGPUStatus(svc))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "gpu_processes",
		Description: "只读列出当前占用 GPU 的进程(PID/进程名/占用显存)。\n\n**同名异义**:NVIDIA 给出精确的 (PID → GPU 序号 → used_memory) 映射;AMD rocm-smi --showpids 只给\"占用 GPU 数\"不给索引,故 gpu_indices 为空 + 进程级 note;Intel intel_gpu_top clients 只给引擎繁忙度,未给显存与 GPU 索引,同样留空。\n\n参数:\n    gpu: GPU 全局序号(可选;省略 = 全部进程)。指定后只保留能映射到该 GPU 的进程(AMD/Intel 因 gpu_indices 为空 → 全部过滤掉,note 写明)。\n\n返回:\n    {\"processes\": [{\"pid\": 1234, \"name\": \"python\", \"vendor\": \"nvidia\", \"gpu_indices\": [0], \"memory_mib\": 1024.0, \"note\": \"...\"}], \"note\": \"...\"}。",
		InputSchema: gpuSelectSchema,
		Annotations: annotations,
	}, handleGPUProcesses(svc))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "gpu_memory",
		Description: "只读返回每 GPU 显存详情(总/已用/空闲,单位 MiB)+ 可映射到该 GPU 的进程列表。\n\nAMD 原生单位是字节(B),已在内部 ÷ 1024² 换算 MiB;Intel intel_gpu_top 未暴露 VRAM 总量 → has_memory=false。FreeMiB 在厂商只给 total/used 时由 total-used 推导。\n\n参数:\n    gpu: GPU 全局序号(可选;省略 = 全部)。\n\n返回:\n    {\"devices\": [{\"index\": 0, \"vendor\": \"...\", \"has_memory\": true, \"total_mib\": 24564.0, \"used_mib\": 1234.0, \"free_mib\": 23330.0, \"processes\": [...]}], \"note\": \"...\"}。",
		InputSchema: gpuSelectSchema,
		Annotations: annotations,
	}, handleGPUMemory(svc))

	return server
}

// handleGPUStatus 把 MCP 入参转 gpuSelectArgs 后执行;越界/CLI 错误以工具
// 错误结果返回,不 panic。
func handleGPUStatus(svc *service) func(context.Context, *mcp.CallToolRequest, gpuSelectIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in gpuSelectIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.Status(ctx, gpuSelectArgs{GPU: in.GPU})
		if err != nil {
			return raisedError("gpu_status", err), nil, nil
		}
		return jsonResult(res), nil, nil
	}
}

// handleGPUProcesses 同 handleGPUStatus。
func handleGPUProcesses(svc *service) func(context.Context, *mcp.CallToolRequest, gpuSelectIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in gpuSelectIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.Processes(ctx, gpuSelectArgs{GPU: in.GPU})
		if err != nil {
			return raisedError("gpu_processes", err), nil, nil
		}
		return jsonResult(res), nil, nil
	}
}

// handleGPUMemory 同 handleGPUStatus。
func handleGPUMemory(svc *service) func(context.Context, *mcp.CallToolRequest, gpuSelectIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in gpuSelectIn) (*mcp.CallToolResult, any, error) {
		res, err := svc.Memory(ctx, gpuSelectArgs{GPU: in.GPU})
		if err != nil {
			return raisedError("gpu_memory", err), nil, nil
		}
		return jsonResult(res), nil, nil
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
