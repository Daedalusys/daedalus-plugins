// main_test.go 验证 MCP 服务器装配:工具注册/入参 schema/结果形态/握手生命周期。
//
// 服务层被替换为 fakeRunner 注入的 service,测试零触碰真实 smartctl 与磁盘;
// 唯一例外是握手用例(dial 本地 stdio),也不触盘。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectSession 建立一对内存 stdio 连接并初始化 MCP 会话,返回已 connect 的
// client session 与 server session 的清理函数。
func connectSession(t *testing.T, svc *service) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	serverT, clientT := mcp.NewInMemoryTransports()
	server := newServer(svc)

	ss, err := server.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// listToolNames 通过 tools/list 拉取服务端注册的工具名集合。
func listToolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	return names
}

// TestHandshakeFourTools 握手后 tools/list 必须逐字含 4 个工具名
// (与 manifest tool 名一致)。
func TestHandshakeFourTools(t *testing.T) {
	cs := connectSession(t, newService())
	got := listToolNames(t, cs)
	want := map[string]bool{
		"smart_list":       false,
		"smart_health":     false,
		"smart_attributes": false,
		"smart_test":       false,
	}
	for _, n := range got {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, seen := range want {
		if !seen {
			t.Errorf("工具 %q 未注册;实际: %v", n, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("注册工具数 = %d, want 4: %v", len(got), got)
	}
}

// TestSmartDiskSchema_Required disk 必填,且带白名单 pattern。
func TestSmartDiskSchema_Required(t *testing.T) {
	if len(smartDiskSchema.Required) != 1 || smartDiskSchema.Required[0] != "disk" {
		t.Errorf("smartDiskSchema.Required = %v, want [disk]", smartDiskSchema.Required)
	}
	disk, ok := smartDiskSchema.Properties["disk"]
	if !ok {
		t.Fatal("smartDiskSchema 缺 disk 字段")
	}
	if disk.Pattern == "" {
		t.Errorf("disk.pattern 应白名单正则, got 空")
	}
}

// TestSmartTestSchema_KindEnum kind 必须是 short|long 枚举。
func TestSmartTestSchema_KindEnum(t *testing.T) {
	if len(smartTestSchema.Required) != 1 || smartTestSchema.Required[0] != "disk" {
		t.Errorf("smartTestSchema.Required = %v, want [disk]", smartTestSchema.Required)
	}
	kind, ok := smartTestSchema.Properties["kind"]
	if !ok {
		t.Fatal("smartTestSchema 缺 kind")
	}
	if len(kind.Enum) != 2 {
		t.Fatalf("kind enum = %v, want 2 项", kind.Enum)
	}
	seen := map[string]bool{}
	for _, e := range kind.Enum {
		seen[fmt.Sprint(e)] = true
	}
	if !seen["short"] || !seen["long"] {
		t.Errorf("kind enum = %v, want short|long", kind.Enum)
	}
}

// TestCallTool_SmartList 端到端调用 smart_list:fakeRunner 喂 scan 夹具,
// 结果 JSON 含 3 disk。
func TestCallTool_SmartList(t *testing.T) {
	svc, fr := newFakeService(fakeResult{lines: splitFixture(t, "scan.txt")})
	cs := connectSession(t, svc)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "smart_list"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("smart_list 不应错误: %+v", res)
	}
	if fr.calls != 1 {
		t.Errorf("calls = %d, want 1", fr.calls)
	}
	text := firstText(t, res)
	var got ScanResult
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("结果非 JSON: %v\n%s", err, text)
	}
	if len(got.Disks) != 3 {
		t.Errorf("disks = %d, want 3: %+v", len(got.Disks), got.Disks)
	}
}

// TestCallTool_SmartHealth_Passed 端到端 smart_health 通过态。
func TestCallTool_SmartHealth_Passed(t *testing.T) {
	svc, _ := newFakeService(fakeResult{lines: splitFixture(t, "health-passed.txt")})
	cs := connectSession(t, svc)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "smart_health",
		Arguments: map[string]any{"disk": "/dev/sda"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("不应错误: %+v", res)
	}
	var got HealthResult
	if err := json.Unmarshal([]byte(firstText(t, res)), &got); err != nil {
		t.Fatalf("结果非 JSON: %v", err)
	}
	if !got.Passed || got.ExitBitmask != 0 {
		t.Errorf("健康态错: %+v", got)
	}
}

// TestCallTool_SmartHealth_InvalidDisk 注入 disk 必须被拒(工具错误或 MCP
// schema 校验错误均可),不 panic、不 fork。schema 层白名单 pattern 通常在
// handler 之前即拦下,故这里两种形态都接受。
func TestCallTool_SmartHealth_InvalidDisk(t *testing.T) {
	svc, fr := newFakeService()
	cs := connectSession(t, svc)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "smart_health",
		Arguments: map[string]any{"disk": "/dev/../etc/passwd"},
	})
	if err != nil {
		t.Fatalf("CallTool 应返回工具结果而非传输错误: %v", err)
	}
	if !res.IsError {
		t.Fatalf("非法 disk 应 IsError=true: %+v", res)
	}
	if fr.calls != 0 {
		t.Errorf("不应 fork, calls=%d", fr.calls)
	}
	text := firstText(t, res)
	if !strings.Contains(text, "smart_health") && !strings.Contains(text, "pattern") {
		t.Errorf("错误文本未指向校验失败: %q", text)
	}
}

// TestCallTool_SmartAttributes 端到端属性解析。
func TestCallTool_SmartAttributes(t *testing.T) {
	svc, _ := newFakeService(fakeResult{lines: splitFixture(t, "attributes-ata.txt")})
	cs := connectSession(t, svc)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "smart_attributes",
		Arguments: map[string]any{"disk": "/dev/sda"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("不应错误: %+v", res)
	}
	var got AttributeSet
	if err := json.Unmarshal([]byte(firstText(t, res)), &got); err != nil {
		t.Fatalf("结果非 JSON: %v", err)
	}
	if got.Attrs["Power_On_Hours"] != 8760 {
		t.Errorf("Power_On_Hours = %d", got.Attrs["Power_On_Hours"])
	}
}

// TestCallTool_SmartTest_L1Deferred 端到端 smart_test:不 fork,started=false。
func TestCallTool_SmartTest_L1Deferred(t *testing.T) {
	svc, fr := newFakeService()
	cs := connectSession(t, svc)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "smart_test",
		Arguments: map[string]any{"disk": "/dev/sda", "kind": "short"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("不应错误: %+v", res)
	}
	if fr.calls != 0 {
		t.Errorf("smart_test 不应 fork, calls=%d", fr.calls)
	}
	var got SmartTestResult
	if err := json.Unmarshal([]byte(firstText(t, res)), &got); err != nil {
		t.Fatalf("结果非 JSON: %v", err)
	}
	if got.Started {
		t.Errorf("Started 应 false")
	}
	if !strings.Contains(got.Note, "L1") {
		t.Errorf("Note = %q", got.Note)
	}
}

// TestJSONResult_NonASCII 对应 FastMCP ensure_ascii=False:中文与 "<>&" 原样
// 输出(不被 HTML 转义)。
func TestJSONResult_NonASCII(t *testing.T) {
	res := jsonResult(map[string]string{"msg": "温度 <正常> & 健康"})
	if len(res.Content) != 1 {
		t.Fatalf("content = %d", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content 类型 = %T", res.Content[0])
	}
	if !strings.Contains(tc.Text, "温度 <正常> & 健康") {
		t.Errorf("非 ASCII/HTML 字符被转义: %q", tc.Text)
	}
}

// TestRaisedError_Format 工具错误文本形态。
func TestRaisedError_Format(t *testing.T) {
	res := raisedError("smart_health", errors.New("boom"))
	if !res.IsError {
		t.Errorf("IsError 应 true")
	}
	if got := firstText(t, res); got != "Error executing tool smart_health: boom" {
		t.Errorf("文本 = %q", got)
	}
}

// TestTextResult_Shape 成功结果单文本块、非错误。
func TestTextResult_Shape(t *testing.T) {
	res := textResult("hello")
	if res.IsError {
		t.Errorf("不应 IsError")
	}
	if len(res.Content) != 1 {
		t.Fatalf("content = %d", len(res.Content))
	}
}

// TestIsCleanShutdown 正常/异常关闭归类。
func TestIsCleanShutdown(t *testing.T) {
	clean := []error{context.Canceled, io.EOF, errors.New("server is closing: bye")}
	for _, err := range clean {
		if !isCleanShutdown(err) {
			t.Errorf("isCleanShutdown(%v) 应 true", err)
		}
	}
	dirty := []error{errors.New("boom"), context.DeadlineExceeded, errors.New("server is not closing")}
	for _, err := range dirty {
		if isCleanShutdown(err) {
			t.Errorf("isCleanShutdown(%v) 应 false", err)
		}
	}
}

// firstText 取结果首个文本块内容。
func firstText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("结果无 content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] 类型 = %T", res.Content[0])
	}
	return tc.Text
}
