// daedalus-sysinfo 的行为测试:内存内 MCP 往返断言 tools/list 与
// sysinfo_server.py 同名/同描述/同注解,并用 testdata 根目录 +
// 注入 exec/disk 做无特权、无 ip/rpm 依赖的端到端验证。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/sysinfo"
)

// fakeExec 脚本化命令替身(耗尽后重复最后一步)。
type fakeExec struct {
	calls [][]string
	steps []fakeStep
	idx   int
}

type fakeStep struct {
	stdout, stderr string
	code           int
	err            error
}

func (f *fakeExec) run(_ context.Context, name string, args []string) (string, string, int, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	s := f.steps[f.idx]
	if f.idx < len(f.steps)-1 {
		f.idx++
	}
	return s.stdout, s.stderr, s.code, s.err
}

// connectSession 建立内存内客户端/服务器会话(冒烟同形态)。
func connectSession(t *testing.T, svc *sysinfo.Service) (*mcp.ClientSession, context.Context) {
	t.Helper()
	server := newServer(svc)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "sysinfo-test-client", Version: "0.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("MCP 握手失败: %v", err)
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Errorf("关闭会话失败: %v", err)
		}
		if err := <-serverDone; err != nil {
			t.Errorf("服务器退出异常: %v", err)
		}
	})
	return session, ctx
}

// callToolJSON 调用无参工具,断言非错误并把文本块解析为 JSON map。
func callToolJSON(t *testing.T, session *mcp.ClientSession, ctx context.Context, tool string) map[string]any {
	t.Helper()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool})
	if err != nil {
		t.Fatalf("tools/call %s 传输失败: %v", tool, err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("tools/call %s 无内容块", tool)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("tools/call %s 回包非文本: %T", tool, res.Content[0])
	}
	if res.IsError {
		t.Fatalf("tools/call %s 返回错误: %s", tool, text.Text)
	}
	// py 版工具返回 dict → 文本必须是合法 JSON 对象(indent=2 序列化)。
	var out map[string]any
	if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("tools/call %s 回包非 JSON 对象: %v (%q)", tool, err, text.Text)
	}
	return out
}

// testdataRoot 定位 daedalus-sdk/sysinfo/testdata/<name>(fixture 单一来源,
// 随包迁入 SDK,避免在 cmd 测试里复制 testdata)。
func testdataRoot(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("无法定位本测试文件")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "daedalus-sdk", "sysinfo", "testdata", name)
}

// TestToolsList_MatchesPySpec 断言 3 个工具与 py 函数同名、只读注解齐备、
// 无参 schema 为 {"type":"object"}。
func TestToolsList_MatchesPySpec(t *testing.T) {
	session, ctx := connectSession(t, sysinfo.NewService(nil, testdataRoot(t, "root"), nil))
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	if len(res.Tools) != 3 {
		t.Fatalf("工具数量 = %d, want 3", len(res.Tools))
	}

	names := make([]string, 0, 3)
	byName := map[string]*mcp.Tool{}
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
		byName[tool.Name] = tool
	}
	slices.Sort(names)
	// 与 sysinfo_server.py 函数名逐字一致(py:22,59,133)。
	if want := []string{"hardware_info", "network_status", "os_release"}; !slices.Equal(names, want) {
		t.Errorf("工具名 = %v, want %v", names, want)
	}

	for _, tool := range res.Tools {
		a := tool.Annotations
		if a == nil || !a.ReadOnlyHint {
			t.Errorf("%s 注解缺失或非只读: %+v", tool.Name, a)
		}
		if a != nil && (a.DestructiveHint == nil || *a.DestructiveHint != false) {
			t.Errorf("%s destructiveHint 应为显式 false: %+v", tool.Name, a.DestructiveHint)
		}
		schema, ok := tool.InputSchema.(map[string]any)
		if !ok || schema["type"] != "object" {
			t.Errorf("%s 无参 schema 异常: %v", tool.Name, tool.InputSchema)
		}
	}

	// 描述关键句(逐字 docstring 对照表在证据文件)。
	if !strings.Contains(byName["os_release"].Description, "解析并返回操作系统发行版信息（只读）。") {
		t.Errorf("os_release 描述漂移: %q", byName["os_release"].Description)
	}
	if !strings.Contains(byName["hardware_info"].Description, "返回 CPU、内存和磁盘使用信息（只读）。") {
		t.Errorf("hardware_info 描述漂移: %q", byName["hardware_info"].Description)
	}
	if !strings.Contains(byName["network_status"].Description, "返回网络接口和地址状态（只读）。") {
		t.Errorf("network_status 描述漂移: %q", byName["network_status"].Description)
	}
}

// TestOSRelease_EndToEnd 验证 os_release 工具回包 = testdata 解析结果。
func TestOSRelease_EndToEnd(t *testing.T) {
	session, ctx := connectSession(t, sysinfo.NewService(nil, testdataRoot(t, "root"), nil))
	out := callToolJSON(t, session, ctx, "os_release")
	if out["ID"] != "daedalus" || out["NAME"] != "Daedalus OS" {
		t.Errorf("os_release 回包 = %v", out)
	}
	if _, ok := out["error"]; ok {
		t.Errorf("正常样本不应有 error: %v", out["error"])
	}
}

// TestHardwareInfo_EndToEnd 验证三层结构、内存白名单与 disk 的 GB/字节双形态。
func TestHardwareInfo_EndToEnd(t *testing.T) {
	const gib = 1024 * 1024 * 1024
	svc := sysinfo.NewService(nil, testdataRoot(t, "root"), func(string) (sysinfo.DiskUsage, error) {
		return sysinfo.DiskUsage{Total: 100 * gib, Used: 32 * gib, Free: 68 * gib}, nil
	})
	session, ctx := connectSession(t, svc)
	out := callToolJSON(t, session, ctx, "hardware_info")

	cpu, _ := out["cpu"].(map[string]any)
	if cpu["model"] != "Fake Test CPU @ 3.50GHz" || cpu["cores"] != float64(3) {
		t.Errorf("cpu = %v", out["cpu"])
	}
	mem, _ := out["memory"].(map[string]any)
	if len(mem) != 5 {
		t.Errorf("memory 键数 = %d, want 5(白名单): %v", len(mem), mem)
	}
	disk, _ := out["disk"].(map[string]any)
	if disk["path"] != "/" ||
		disk["total_bytes"] != float64(100*gib) ||
		disk["total_gb"] != 100.0 || disk["used_gb"] != 32.0 || disk["free_gb"] != 68.0 {
		t.Errorf("disk = %v", disk)
	}
}

// TestNetworkStatus_EndToEnd_FallbackToNetDev 无 ip 环境(注入启动异常)下
// 端到端落到 /proc/net/dev 样本。
func TestNetworkStatus_EndToEnd_FallbackToNetDev(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{err: errors.New(`exec: "ip": executable file not found in $PATH`)}}}
	svc := sysinfo.NewService(fe.run, testdataRoot(t, "root"), nil)
	session, ctx := connectSession(t, svc)
	out := callToolJSON(t, session, ctx, "network_status")

	ifaces, ok := out["interfaces"].(map[string]any)
	if !ok {
		t.Fatalf("应回退到 /proc/net/dev: %v", out)
	}
	lo, _ := ifaces["lo"].(map[string]any)
	if lo["rx_bytes"] != float64(11111) || lo["tx_bytes"] != float64(22222) {
		t.Errorf("lo = %v", ifaces["lo"])
	}
	// 两级 ip 都尝试过才落到第三级。
	want := [][]string{{"ip", "-j", "addr", "show"}, {"ip", "addr", "show"}}
	if !slices.EqualFunc(fe.calls, want, slices.Equal) {
		t.Errorf("调用序列 = %v, want %v", fe.calls, want)
	}
}

// TestNetworkStatus_EndToEnd_IpJson 一级命中时直接返回 interfaces 数组。
func TestNetworkStatus_EndToEnd_IpJson(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{stdout: `[{"ifname":"eth0","operstate":"UP"}]`, code: 0}}}
	svc := sysinfo.NewService(fe.run, testdataRoot(t, "emptyroot"), nil)
	session, ctx := connectSession(t, svc)
	out := callToolJSON(t, session, ctx, "network_status")
	list, ok := out["interfaces"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("interfaces = %v", out["interfaces"])
	}
	if len(fe.calls) != 1 {
		t.Errorf("命中后仍继续回退: %v", fe.calls)
	}
}

// TestNetworkStatus_MisleadingSuccessSentinel 对抗:全部回退落空时必须给
// py:196 的 error 键,而不是空/成功的假象。
func TestNetworkStatus_MisleadingSuccessSentinel(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{code: 127, stderr: "not found"}}}
	svc := sysinfo.NewService(fe.run, testdataRoot(t, "emptyroot"), nil)
	session, ctx := connectSession(t, svc)
	out := callToolJSON(t, session, ctx, "network_status")
	if want := "Unable to determine network status"; out["error"] != want {
		t.Errorf("error = %v, want %q", out["error"], want)
	}
}

// TestHostOsReleaseReadable 冒烟:真实 "/" 根下 os-release 候选可读时,
// 工具必须返回含 ID 或 NAME 的发行版信息(证明注入未破坏生产路径形态)。
func TestHostOsReleaseReadable(t *testing.T) {
	if _, err := os.Stat("/usr/lib/os-release"); err != nil {
		if _, err2 := os.Stat("/etc/os-release"); err2 != nil {
			t.Skip("宿主无 os-release,跳过")
		}
	}
	svc := sysinfo.NewService(nil, "/", nil)
	got := svc.OSRelease()
	if _, ok := got["error"]; ok {
		t.Fatalf("宿主 os-release 读取失败: %v", got["error"])
	}
	if got["ID"] == nil && got["NAME"] == nil {
		t.Errorf("宿主 os-release 缺 ID/NAME: %v", got)
	}
}
