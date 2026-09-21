// daedalus-service 行为测试:骨架层(serverName / isCleanShutdown / 握手
// 两工具)+ todo 6 的 service.query 工具层 + 共享夹具机制
// (fakeSystemctl / connectSession / findTool)。todo 7 的 service.list
// 测试因 250 纯 LOC 上限分居 main_list_test.go。systemctl 一律经包级
// systemctlBinary 注入 t.TempDir() 下的 shell 夹具(输出固定夹具表),
// 绝不触碰宿主真实 systemd——测试确定性 + 隔离性双重保证。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/objectmodel"
)

// TestIsCleanShutdown 断言三类"正常结束"err 均归类为干净退出,
// 且真实故障 err 不被误归类(否则 stderr 错误通道会被静默吞掉)。
func TestIsCleanShutdown(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// 客户端断开:context.Canceled(含包装形态,errors.Is 穿透语义)。
		{"context.Canceled", context.Canceled, true},
		{"context.Canceled 包装", fmtWrap(context.Canceled), true},
		// stdin EOF:裸 io.EOF 与包装形态。
		{"io.EOF", io.EOF, true},
		{"io.EOF 包装", fmtWrap(io.EOF), true},
		// SDK 内部 jsonrpc2.ErrServerClosing:位于 internal 包,只能按消息前缀归类。
		{"server is closing 前缀", errors.New("server is closing: session terminated"), true},
		// 反例:真实故障必须走非零退出 + stderr 上报;相似但非前缀的消息不得误判。
		{"普通错误", errors.New("boom"), false},
		{"非前缀相似串", errors.New("closing server now"), false},
	}
	for _, tc := range cases {
		if got := isCleanShutdown(tc.err); got != tc.want {
			t.Errorf("%s: isCleanShutdown(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

// fmtWrap 以 %w 包装错误,验证 errors.Is 穿透而非直接相等匹配。
func fmtWrap(err error) error { return fmt.Errorf("mcp: %w", err) }

// TestNewServer_HandshakeTwoTools 冒烟:服务器标识常量逐字钉死(todo 5),
// 且 todo 7 起恰有 2 个工具 service.query + service.list(集合恒等断言,
// 多注册/漏注册都在此爆红)。
func TestNewServer_HandshakeTwoTools(t *testing.T) {
	if serverName != "daedalus-service" {
		t.Errorf("serverName = %q, want %q", serverName, "daedalus-service")
	}
	session, ctx := connectSession(t)
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	if len(res.Tools) != 2 {
		t.Fatalf("工具数 = %d, want 2(todo 7 注册 service.list)", len(res.Tools))
	}
	names := []string{res.Tools[0].Name, res.Tools[1].Name}
	slices.Sort(names)
	if names[0] != "service.list" || names[1] != "service.query" {
		t.Errorf("工具集 = %v, want {service.list, service.query}", names)
	}
}

// findTool 经 tools/list 按名称取回指定工具声明(不依赖 SDK 返回顺序)。
func findTool(t *testing.T, session *mcp.ClientSession, ctx context.Context, name string) *mcp.Tool {
	t.Helper()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	for _, tool := range res.Tools {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("tools/list 缺 %q:共 %d 个", name, len(res.Tools))
	return nil
}

// connectSession 建立内存内 MCP 会话(同 cmd/daedalus-pkg 实证形态),
// 并在测试结束时校验会话与服务器均干净退出。
func connectSession(t *testing.T) (*mcp.ClientSession, context.Context) {
	t.Helper()
	server := newServer()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "service-test-client", Version: "0.0.0"}, nil)
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

// callTool 调用 service.query 并返回 (结果, 首个文本块)。
func callTool(t *testing.T, session *mcp.ClientSession, ctx context.Context, args map[string]any) (*mcp.CallToolResult, string) {
	t.Helper()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "service.query", Arguments: args})
	if err != nil {
		t.Fatalf("tools/call service.query 传输失败: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("tools/call service.query 无内容块")
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("tools/call service.query 回包非文本: %T", res.Content[0])
	}
	return res, text.Text
}

// fakeSystemctl 在 t.TempDir() 下生成假 systemctl:把收到的 argv 逐行
// 追加到 capture 文件,再向 stdout 打印固定 output。以 systemctlBinary
// 覆写完成注入(测试结束自动还原),返回 capture 路径。
func fakeSystemctl(t *testing.T, output string) string {
	t.Helper()
	dir := t.TempDir()
	capture := filepath.Join(dir, "argv.txt")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> " + strconv.Quote(capture) +
		"\ncat <<'FIXTURE'\n" + output + "FIXTURE\n"
	path := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("写入假 systemctl 失败: %v", err)
	}
	orig := systemctlBinary
	systemctlBinary = path
	t.Cleanup(func() { systemctlBinary = orig })
	return capture
}

// happyFixtureOutput 是 sshd.service(未运行态)的固定 systemctl show 表,
// 键与 curated 属性白名单逐字一致。
const happyFixtureOutput = "MainPID=0\n" +
	"LoadState=loaded\n" +
	"ActiveState=inactive\n" +
	"SubState=dead\n" +
	"UnitFileState=enabled\n" +
	"ActiveEnterTimestamp=\n" +
	"FragmentPath=/usr/lib/systemd/system/sshd.service\n"

// TestServiceQuery_Happy 端到端:夹具报 ActiveState=inactive,断言回包
// 是 jsonResult 缩进形态的 objectmodel.ServiceState,且 Properties 逐字
// 来自夹具输出(反造假:凭输入凭空拼 {kind,name} 而无 Properties 的
// handler 必然在此失败)。同时钉 argv:show + <unit>.service + 白名单
// --property 逐项全等(全等本身即排除 shell 包装与 -c 注入)。
func TestServiceQuery_Happy(t *testing.T) {
	capture := fakeSystemctl(t, happyFixtureOutput)
	session, ctx := connectSession(t)

	res, text := callTool(t, session, ctx, map[string]any{"name": "sshd"})
	if res.IsError {
		t.Fatalf("合法查询被误判为错误: %s", text)
	}
	// 反造假硬断言:响应文本必须携带夹具里的真实键值。
	if !strings.Contains(text, `"ActiveState": "inactive"`) {
		t.Errorf("回包缺夹具值 \"ActiveState\": \"inactive\":\n%s", text)
	}
	var state objectmodel.ServiceState
	if err := json.Unmarshal([]byte(text), &state); err != nil {
		t.Fatalf("回包不是合法 JSON: %v\n%s", err, text)
	}
	if state.Kind != "service" || state.Name != "sshd.service" || state.DesiredState != "" {
		t.Errorf("载荷骨架 = %+v, want kind=service name=sshd.service desired_state=\"\"", state)
	}
	for _, p := range queryProperties {
		if _, ok := state.Properties[p]; !ok {
			t.Errorf("Properties 缺白名单键 %q: %v", p, state.Properties)
		}
	}
	if got := state.Properties["FragmentPath"]; got != "/usr/lib/systemd/system/sshd.service" {
		t.Errorf("FragmentPath = %q, want 夹具原文", got)
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("假 systemctl 未被调用: %v", err)
	}
	want := []string{"show", "sshd.service"}
	for _, p := range queryProperties {
		want = append(want, "--property="+p)
	}
	if argv := strings.Fields(string(raw)); !slices.Equal(argv, want) {
		t.Errorf("argv = %v,\nwant %v", argv, want)
	}
}

// TestServiceQuery_InvalidNamesNeverExecuted 失败面 (a):空名、路径分隔符、
// ".." 遍历、空白、shell 元字符、非 ASCII、空字节全部 IsError=true,
// 且在 argv 构造前被拒(假 systemctl 从未被拉起,capture 文件不存在)。
func TestServiceQuery_InvalidNamesNeverExecuted(t *testing.T) {
	capture := fakeSystemctl(t, happyFixtureOutput)
	session, ctx := connectSession(t)

	for _, name := range []string{"", "../etc/passwd", "a/b", "a\\b", "a b", "a;b", "a|b", "..", "sshd.", "café", "$(id)", "\x00"} {
		res, text := callTool(t, session, ctx, map[string]any{"name": name})
		if !res.IsError {
			t.Errorf("非法名 %q 竟然成功: %s", name, text)
		}
	}
	if _, err := os.Stat(capture); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("校验失败仍触发了外部命令(capture 存在): %v", err)
	}
}

// TestServiceQuery_UnitLoadStateRejected 失败面 (b):夹具 LoadState 为
// not-found / masked 时,皆以逐字文案 "error: unit <name>.service not found"
// 拒绝(计划 pin 的两种 LoadState 表驱动钉死)。
func TestServiceQuery_UnitLoadStateRejected(t *testing.T) {
	cases := []struct{ loadState, name, want string }{
		{"not-found", "missing", "error: unit missing.service not found"},
		{"masked", "crypto", "error: unit crypto.service not found"},
	}
	for _, tc := range cases {
		fakeSystemctl(t, "LoadState="+tc.loadState+"\n")
		session, ctx := connectSession(t)
		res, text := callTool(t, session, ctx, map[string]any{"name": tc.name})
		if !res.IsError {
			t.Fatalf("%s 单元竟然成功: %s", tc.loadState, text)
		}
		if text != tc.want {
			t.Errorf("错误文本 = %q, want %q", text, tc.want)
		}
	}
}

// TestServiceQuery_ToolSpec 失败面 (c) 对应物:经 tools/list 断言工具
// 声明面——名称/中文描述/name-only required schema/四项注解
// (OpenWorldHint=false 是本服务器与 pkg 的差异点,必须显式钉)。
func TestServiceQuery_ToolSpec(t *testing.T) {
	session, ctx := connectSession(t)
	tool := findTool(t, session, ctx, "service.query")
	if !strings.Contains(tool.Description, "只读查询 systemd 单元属性") {
		t.Errorf("描述漂移(中文规格): %q", tool.Description)
	}
	schema, ok := tool.InputSchema.(map[string]any)
	if !ok || schema["type"] != "object" {
		t.Fatalf("InputSchema 非 object: %#v", tool.InputSchema)
	}
	if req, _ := schema["required"].([]any); len(req) != 1 || req[0] != "name" {
		t.Errorf("schema required = %v, want [name]", schema["required"])
	}
	props, _ := schema["properties"].(map[string]any)
	if name, ok := props["name"].(map[string]any); len(props) != 1 || !ok || name["type"] != "string" {
		t.Errorf("schema properties = %v, want 仅 name:string", props)
	}
	a := tool.Annotations
	if a == nil {
		t.Fatal("缺 Annotations")
	}
	if !a.ReadOnlyHint || !a.IdempotentHint || a.DestructiveHint == nil || *a.DestructiveHint ||
		a.OpenWorldHint == nil || *a.OpenWorldHint {
		t.Errorf("注解集应为 只读/非破坏(显式false)/幂等/封闭世界(显式false): %+v", a)
	}
}

// TestNormalizeUnitName 直接钉名字校验 + 隐式 .service 补全规则
// (argv 构造前的最后一道纯函数防线)。wantErr 行为拒绝面。
func TestNormalizeUnitName(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"sshd", "sshd.service", false},                   // 隐式补后缀
		{"sshd.service", "sshd.service", false},           // 已带后缀不得重复追加
		{"getty@tty1", "getty@tty1.service", false},       // 模板实例 '@' 合法
		{"my_unit-2.v1", "my_unit-2.v1.service", false},   // 下划线/连字符/点合法
		{"user@1000.service", "user@1000.service", false}, // 模板 + 已有后缀
		{"", "", true}, {"..", "", true}, {"sshd.", "", true}, // 空 + 遍历/拼接 ".." 形态
		{"a/b", "", true}, {"a\\b", "", true}, // 路径分隔符
		{"a b", "", true}, {"a;b", "", true}, {"$(id)", "", true}, // 空白与 shell 注入
		{"café", "", true}, {"x\x00y", "", true}, // 非 ASCII 与空字节
	}
	for _, tc := range cases {
		got, err := normalizeUnitName(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("normalizeUnitName(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
		} else if !tc.wantErr && got != tc.want {
			t.Errorf("normalizeUnitName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
