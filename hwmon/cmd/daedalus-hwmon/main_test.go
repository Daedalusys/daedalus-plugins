// hwmon MCP 服务器的会话层测试:握手工具集、六工具端到端调用与降级路径。
// 数据源经 EnvHwmonRoot 指向测试夹具(独立于 main_test 的 fixtureRoot,
// 隔离各测试状态);RAPL 测试通过显式注入 baseline 避免依赖真实时间差。
package main

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectSession 建立内存内 MCP 会话(同 proc 实证形态),并以 fresh
// fixture service 装配服务器,确保每个用例独立干净。
func connectSession(t *testing.T) (*mcp.ClientSession, context.Context, *service) {
	t.Helper()
	svc := newService(fixtureRoot)
	server := newServer(svc)
	ct, st := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, st) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "hwmon-test-client", Version: "0.0.0"}, nil)
	sess, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("MCP 握手失败: %v", err)
	}
	t.Cleanup(func() {
		if err := sess.Close(); err != nil {
			t.Errorf("会话关闭失败: %v", err)
		}
		if err := <-done; err != nil && !isCleanShutdown(err) {
			t.Errorf("服务器退出异常: %v", err)
		}
	})
	return sess, ctx, svc
}

// callTool 调用工具并返回原始文本与 isError。
func callTool(t *testing.T, s *mcp.ClientSession, ctx context.Context,
	tool string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s) 传输失败: %v", tool, err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("%s 结果块数 = %d", tool, len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s 结果块非 TextContent: %T", tool, res.Content[0])
	}
	return tc.Text, res.IsError
}

func callJSON[T any](t *testing.T, s *mcp.ClientSession, ctx context.Context,
	tool string, args map[string]any) T {
	t.Helper()
	text, isErr := callTool(t, s, ctx, tool, args)
	if isErr {
		t.Fatalf("%s 意外报错: %s", tool, text)
	}
	var out T
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("%s 输出非 JSON: %v\n%s", tool, err, text)
	}
	return out
}

// TestHandshakeSixTools 握手期 tools/list 必须返回六个工具,名称与
// manifest.tools 逐字一致(76 脚本构建期即核对该集合)。
func TestHandshakeSixTools(t *testing.T) {
	sess, ctx, _ := connectSession(t)
	res, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	got := make([]string, 0, len(res.Tools))
	for _, tl := range res.Tools {
		got = append(got, tl.Name)
	}
	slices.Sort(got)
	want := []string{
		"hwmon_battery", "hwmon_fans", "hwmon_power",
		"hwmon_temperatures", "hwmon_thermal_zones", "hwmon_voltages",
	}
	if !slices.Equal(got, want) {
		t.Errorf("工具集 = %v\nwant %v", got, want)
	}
}

// TestToolsE2E 端到端跑六工具:RAPL 在 E2E 前显式注入 baseline 以验证差分逻辑
// (避免依赖真实系统时间差;fixture energy_uj 静态,无基线则恒返空)。
func TestToolsE2E(t *testing.T) {
	sess, ctx, svc := connectSession(t)

	temps := callJSON[[]temperature](t, sess, ctx, "hwmon_temperatures", map[string]any{})
	if len(temps) != 3 || temps[0].Label != "core0" || temps[0].Celsius != 45.0 {
		t.Errorf("hwmon_temperatures = %+v", temps)
	}

	fans := callJSON[[]fan](t, sess, ctx, "hwmon_fans", map[string]any{})
	if len(fans) != 1 || fans[0].RPM != 1200 {
		t.Errorf("hwmon_fans = %+v", fans)
	}

	volts := callJSON[[]voltage](t, sess, ctx, "hwmon_voltages", map[string]any{})
	if len(volts) != 2 || volts[0].Volts != 0.85 {
		t.Errorf("hwmon_voltages = %+v", volts)
	}

	zones := callJSON[[]thermalZone](t, sess, ctx, "hwmon_thermal_zones", map[string]any{})
	if len(zones) != 2 || zones[0].Celsius != 44.0 {
		t.Errorf("hwmon_thermal_zones = %+v", zones)
	}

	bat := callJSON[[]battery](t, sess, ctx, "hwmon_battery", map[string]any{})
	if len(bat) != 1 || bat[0].Capacity != 87 {
		t.Errorf("hwmon_battery = %+v", bat)
	}

	// 注入 baseline:fixture energy_uj=3000000,上轮 1000000,间隔约 1s → 约 2W。
	// handler 用 time.Now(),故时间差含微秒级抖动,这里用宽容差而非精确等值;
	// 精确差分数学由 hwmon_test.go 的 TestPowerDelta 钉死。
	svc.haveRAPL = true
	svc.lastEnergyUj = 1_000_000
	svc.lastRAPLTime = time.Now().Add(-time.Second)
	pwr := callJSON[[]powerReading](t, sess, ctx, "hwmon_power", map[string]any{})
	if len(pwr) != 1 || pwr[0].Watts < 1.9 || pwr[0].Watts > 2.1 {
		t.Errorf("hwmon_power = %+v(期望约 2W)", pwr)
	}
}

// TestEmptyRootE2E 空根应六个工具都返空数组且无错误(优雅降级)。
func TestEmptyRootE2E(t *testing.T) {
	svc := newService(t.TempDir())
	server := newServer(svc)
	ct, st := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, st) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "hwmon-empty", Version: "0.0.0"}, nil)
	sess, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("MCP 握手失败: %v", err)
	}
	t.Cleanup(func() {
		_ = sess.Close()
		<-done
	})

	for _, tool := range []string{
		"hwmon_temperatures", "hwmon_fans", "hwmon_voltages",
		"hwmon_power", "hwmon_battery", "hwmon_thermal_zones",
	} {
		text, isErr := callTool(t, sess, ctx, tool, map[string]any{})
		if isErr {
			t.Errorf("%s 空根不应报错: %s", tool, text)
			continue
		}
		var arr []json.RawMessage
		if err := json.Unmarshal([]byte(text), &arr); err != nil {
			t.Errorf("%s 空根输出非数组: %v\n%s", tool, err, text)
		}
		if len(arr) != 0 {
			t.Errorf("%s 空根应空数组: %s", tool, text)
		}
	}
}
