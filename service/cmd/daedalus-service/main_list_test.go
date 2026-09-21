// todo 7 的 service.list 工具层测试。systemctl 注入复用 main_test.go 的
// fakeSystemctl 机制(KEY=VALUE capture + heredoc 打印固定 list-units 表),
// 与 service.query 测试同型:夹具确定性 + 零触碰宿主 systemd。
// 与 main_test.go 分文件的原因:250 纯 LOC 上限(T6 已把 main_test.go 压到
// 238,余量不足以容纳 list 全谱测试)。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/objectmodel"
)

// callListTool 调用 service.list 并返回 (结果, 首个文本块)。
func callListTool(t *testing.T, session *mcp.ClientSession, ctx context.Context, args map[string]any) (*mcp.CallToolResult, string) {
	t.Helper()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "service.list", Arguments: args})
	if err != nil {
		t.Fatalf("tools/call service.list 传输失败: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("tools/call service.list 无内容块")
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("tools/call service.list 回包非文本: %T", res.Content[0])
	}
	return res, text.Text
}

// listFixtureOutput 是三行 `systemctl list-units --type=service --all --no-legend`
// 夹具:两行带 ● 状态字形前缀、一行无前缀(未激活单元的空 glyph 位),
// 描述列含空格(验证只取 UNIT/LOAD/ACTIVE/SUB 前四列),外加一行无单元名
// 的垃圾行(应被静默跳过)。sshd/nginx 行均为 loaded active running,
// cron 行为 loaded inactive dead(计划 Happy QA 的 active 断言素材)。
const listFixtureOutput = "● nginx.service loaded active running A high performance web server and a reverse proxy server\n" +
	"  cron.service loaded inactive dead Regular background program processing daemon\n" +
	"● sshd.service loaded active running OpenBSD Secure Shell server\n" +
	"0 tokens processed.\n"

// TestServiceList_Happy 端到端:夹具三单元 → 回包是 JSON 数组、按 Name
// 升序、Properties 逐字来自夹具(反造假:凭输入拼数组元素的 handler 必然
// 在此失败)。nil filter 走默认 "*":argv 恰为五旗标、**无追加过滤参数**
// (capture 全等钉死,同时排除 shell 包装)。
func TestServiceList_Happy(t *testing.T) {
	capture := fakeSystemctl(t, listFixtureOutput)
	session, ctx := connectSession(t)

	res, text := callListTool(t, session, ctx, map[string]any{})
	if res.IsError {
		t.Fatalf("合法列出被误判为错误: %s", text)
	}
	var states []objectmodel.ServiceState
	if err := json.Unmarshal([]byte(text), &states); err != nil {
		t.Fatalf("回包不是合法 JSON 数组: %v\n%s", err, text)
	}
	if len(states) != 3 {
		t.Fatalf("元素数 = %d, want 3(垃圾行应被跳过):\n%s", len(states), text)
	}
	wantNames := []string{"cron.service", "nginx.service", "sshd.service"}
	for i, want := range wantNames {
		if states[i].Name != want {
			t.Errorf("states[%d].Name = %q, want %q(须按 Name 升序)", i, states[i].Name, want)
		}
		if states[i].Kind != "service" || states[i].DesiredState != "" {
			t.Errorf("states[%d] 骨架 = %+v, want kind=service desired_state=\"\"", i, states[i])
		}
	}
	byName := map[string]objectmodel.ServiceState{}
	for _, s := range states {
		byName[s.Name] = s
	}
	for unit, want := range map[string][3]string{
		"sshd.service":  {"loaded", "active", "running"},
		"nginx.service": {"loaded", "active", "running"},
		"cron.service":  {"loaded", "inactive", "dead"},
	} {
		p := byName[unit].Properties
		got := [3]string{p["LoadState"], p["ActiveState"], p["SubState"]}
		if got != want {
			t.Errorf("%s Properties = %v, want %v(夹具逐字)", unit, got, want)
		}
	}
	// 反造假硬断言:响应文本携带夹具真实键值(计划 pin 的 nginx active)。
	if !strings.Contains(text, `"ActiveState": "active"`) {
		t.Errorf("回包缺夹具值 \"ActiveState\": \"active\":\n%s", text)
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("假 systemctl 未被调用: %v", err)
	}
	want := []string{"list-units", "--type=service", "--all", "--no-pager", "--no-legend"}
	if argv := strings.Fields(string(raw)); !slices.Equal(argv, want) {
		t.Errorf("默认 filter 的 argv = %v,\nwant %v(不过滤时不得追加参数)", argv, want)
	}
}

// TestServiceList_ExplicitFilterAppended 显式过滤 sshd → argv 末尾追加
// 该模式(原样 argv 直发,无 .service 强制补全:filter 是模式不是单元名);
// 显式 "*" 与默认等价,同样不追加。
func TestServiceList_ExplicitFilterAppended(t *testing.T) {
	cases := []struct {
		filter string
		want   []string
	}{
		{"sshd", []string{"list-units", "--type=service", "--all", "--no-pager", "--no-legend", "sshd"}},
		{"*", []string{"list-units", "--type=service", "--all", "--no-pager", "--no-legend"}},
	}
	for _, tc := range cases {
		capture := fakeSystemctl(t, listFixtureOutput)
		session, ctx := connectSession(t)
		res, text := callListTool(t, session, ctx, map[string]any{"filter": tc.filter})
		if res.IsError {
			t.Fatalf("合法 filter %q 被误判为错误: %s", tc.filter, text)
		}
		raw, err := os.ReadFile(capture)
		if err != nil {
			t.Fatalf("假 systemctl 未被调用: %v", err)
		}
		if argv := strings.Fields(string(raw)); !slices.Equal(argv, tc.want) {
			t.Errorf("filter=%q argv = %v,\nwant %v", tc.filter, argv, tc.want)
		}
	}
}

// TestServiceList_EmptyFilterRejected 失败面 (b):显式空串 filter →
// IsError=true,且在 exec 前被拒(capture 不存在)。
func TestServiceList_EmptyFilterRejected(t *testing.T) {
	capture := fakeSystemctl(t, listFixtureOutput)
	session, ctx := connectSession(t)

	res, text := callListTool(t, session, ctx, map[string]any{"filter": ""})
	if !res.IsError {
		t.Fatalf("空 filter 竟然成功: %s", text)
	}
	if _, err := os.Stat(capture); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("校验失败仍触发了外部命令(capture 存在): %v", err)
	}
}

// TestServiceList_InvalidFiltersNeverExecuted 失败面延伸:shell glob、
// 遍历、分隔符、元字符、非 ASCII 全部 IsError=true 且零执行——
// "非 '*' 必须过单元名字符类"是防 glob 注入的主防线。
func TestServiceList_InvalidFiltersNeverExecuted(t *testing.T) {
	capture := fakeSystemctl(t, listFixtureOutput)
	session, ctx := connectSession(t)

	for _, filter := range []string{"*.", "sshd*", "../etc", "a/b", "a\\b", "a b", "a;b", "$(id)", "café", "\x00", "a..b"} {
		res, text := callListTool(t, session, ctx, map[string]any{"filter": filter})
		if !res.IsError {
			t.Errorf("非法 filter %q 竟然成功: %s", filter, text)
		}
	}
	if _, err := os.Stat(capture); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("校验失败仍触发了外部命令(capture 存在): %v", err)
	}
}

// TestServiceList_ToolSpec 声明面:名称/中文描述/filter-only 可选 schema
// (required 缺省为空 + Default 字段为 "*")/四项注解与 service.query 同族。
func TestServiceList_ToolSpec(t *testing.T) {
	session, ctx := connectSession(t)
	list := findTool(t, session, ctx, "service.list")

	if !strings.Contains(list.Description, "只读列出") {
		t.Errorf("描述漂移(中文规格): %q", list.Description)
	}
	schema, ok := list.InputSchema.(map[string]any)
	if !ok || schema["type"] != "object" {
		t.Fatalf("InputSchema 非 object: %#v", list.InputSchema)
	}
	if req, ok := schema["required"].([]any); ok && len(req) != 0 {
		t.Errorf("schema required = %v, want 空/缺省(filter 可选)", schema["required"])
	}
	props, _ := schema["properties"].(map[string]any)
	f, ok := props["filter"].(map[string]any)
	if len(props) != 1 || !ok || f["type"] != "string" {
		t.Fatalf("schema properties = %v, want 仅 filter:string", props)
	}
	if f["default"] != "*" {
		t.Errorf("filter default = %v, want \"*\"", f["default"])
	}
	a := list.Annotations
	if a == nil {
		t.Fatal("缺 Annotations")
	}
	if !a.ReadOnlyHint || !a.IdempotentHint || a.DestructiveHint == nil || *a.DestructiveHint ||
		a.OpenWorldHint == nil || *a.OpenWorldHint {
		t.Errorf("注解集应为 只读/非破坏(显式false)/幂等/封闭世界(显式false): %+v", a)
	}
}

// TestValidateListFilter 直接钉过滤模式校验纯函数(argv 构造前的最后防线):
// 空串拒、"*" 通配放行、单元名字符类放行(含 .service 全名与模板 '@')、
// glob/遍历/分隔符/元字符拒。
func TestValidateListFilter(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"*", false}, {"sshd", false}, {"sshd.service", false},
		{"getty@tty1", false}, {"my_unit-2.v1", false},
		{"", true}, {"**", true}, {"sshd*", true}, {"*.service", true},
		{"..", true}, {"a..b", true}, {"a/b", true}, {"a\\b", true},
		{"a b", true}, {"a;b", true}, {"$(id)", true}, {"café", true}, {"x\x00y", true},
	}
	for _, tc := range cases {
		if err := validateListFilter(tc.in); (err != nil) != tc.wantErr {
			t.Errorf("validateListFilter(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
		}
	}
}
