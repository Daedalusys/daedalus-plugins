// Command daedalus-hwmon 是硬件传感器只读 MCP 服务器(stdio JSON-RPC)。
//
// 提供 6 个 L0 工具:温度 / 风扇 / 电压(hwmon)、能耗(RAPL)、电池
// (power_supply)、热区(thermal),全部直读 sysfs。零 exec、零写入、零外部
// 依赖(不集成 lm-sensors);缺文件一律优雅降级为空集。
//
// 工具名与 manifest.tools 逐字一致(76 脚本构建期交叉核对 manifest ↔ 二进制
// tools/list,漂移即构建失败)。
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
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/version"
)

const serverName = "daedalus-hwmon"

// emptyIn 是六个无参工具的输入类型(客户端 arguments 必须是 JSON 对象)。
type emptyIn struct{}

// noArgsSchema 对应无参工具的 {"type": "object"} 输入模式。
var noArgsSchema = &jsonschema.Schema{Type: "object"}

func main() {
	server := newServer(newService(resolveRoot()))

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

	// go-sdk 的 DestructiveHint/OpenWorldHint 为 *bool 且 SDK 未导出取址助手,
	// 按实证形态用局部变量取址(只读传感器必然非破坏性、封闭世界)。
	nonDestructive := false
	closedWorld := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true, // 六工具皆为只读 sysfs 读数
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "hwmon_temperatures",
		Description: "只读返回全部硬件温度传感器(hwmon temp*_input,单位毫摄氏度,输出摄氏度)。\n\n遍历 /sys/class/hwmon/*/temp*_input,优先取对应 *_label,缺失时退化为 tempN。\n\n返回:\n    [{\"label\": \"core0\", \"celsius\": 45.0}]。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(context.Context, *mcp.CallToolRequest, emptyIn) (*mcp.CallToolResult, any, error) {
		return jsonResult(svc.Temperatures()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "hwmon_fans",
		Description: "只读返回全部风扇转速(hwmon fan*_input,单位 RPM)。\n\n遍历 /sys/class/hwmon/*/fan*_input,标签规则同温度。\n\n返回:\n    [{\"label\": \"cpu_fan\", \"rpm\": 1200}]。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(context.Context, *mcp.CallToolRequest, emptyIn) (*mcp.CallToolResult, any, error) {
		return jsonResult(svc.Fans()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "hwmon_voltages",
		Description: "只读返回全部电压传感器(hwmon in*_input,单位毫伏,输出伏)。\n\n遍历 /sys/class/hwmon/*/in*_input,标签规则同温度。\n\n返回:\n    [{\"label\": \"Vcore\", \"volts\": 0.85}]。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(context.Context, *mcp.CallToolRequest, emptyIn) (*mcp.CallToolResult, any, error) {
		return jsonResult(svc.Voltages()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "hwmon_power",
		Description: "只读返回 RAPL 包级平均功率(瓦)。\n\n读 /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj,与上次调用读数求差换算;首次调用只建立基线并返回空集,缺文件同样返回空集。\n\n返回:\n    [{\"domain\": \"intel-rapl:0\", \"watts\": 2.0}]。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, any, error) {
		return jsonResult(svc.Power(time.Now())), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "hwmon_battery",
		Description: "只读返回 BAT0 电池状态与剩余容量(百分比)。\n\n读 /sys/class/power_supply/BAT0/{status,capacity};目录缺失返回空集。\n\n返回:\n    [{\"status\": \"Charging\", \"capacity\": 87}]。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(context.Context, *mcp.CallToolRequest, emptyIn) (*mcp.CallToolResult, any, error) {
		return jsonResult(svc.Battery()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "hwmon_thermal_zones",
		Description: "只读返回全部热区温度(/sys/class/thermal/thermal_zone*,输出摄氏度)。\n\n每个热区读 temp(毫摄氏度)与 type;非 thermal_zoneN 子目录跳过。\n\n返回:\n    [{\"zone\": \"thermal_zone0\", \"type\": \"x86_pkg_temp\", \"celsius\": 44.0}]。",
		InputSchema: noArgsSchema,
		Annotations: annotations,
	}, func(context.Context, *mcp.CallToolRequest, emptyIn) (*mcp.CallToolResult, any, error) {
		return jsonResult(svc.ThermalZones()), nil, nil
	})

	return server
}

// jsonResult 输出 indent=2、不转义 HTML 的 JSON 文本块(家族统一形态)。
func jsonResult(v any) *mcp.CallToolResult {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		}
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.TrimSuffix(buf.String(), "\n")}},
	}
}
