// systemd 全景三工具测试:夹具 systemctl(fakeSystemctl 复用 main_test.go
// 机制)+ 内存 MCP 往返;钉 argv 全等、解析确定性、类型后缀门与 not-found
// 姿势。与 main_list_test.go 分文件同因:250 纯 LOC 上限。
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
)

// callTool 通用 tools/call:返回 (结果, 首个文本块)。
func callNamedTool(t *testing.T, session *mcp.ClientSession, ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, string) {
	t.Helper()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("tools/call %s 传输失败: %v", name, err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("tools/call %s 无内容块", name)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("tools/call %s 回包非文本: %T", name, res.Content[0])
	}
	return res, text.Text
}

func readArgv(t *testing.T, capture string) []string {
	t.Helper()
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("假 systemctl 未被调用: %v", err)
	}
	return strings.Fields(string(raw))
}

// TestNewServer_HandshakeFiveTools 冒烟:服务器标识常量逐字固定,且恰有
// 5 个工具 service.query + service.list + systemd 全景三件套
// (集合恒等断言,多注册/漏注册都在此爆红)。
func TestNewServer_HandshakeFiveTools(t *testing.T) {
	if serverName != "daedalus-service" {
		t.Errorf("serverName = %q, want %q", serverName, "daedalus-service")
	}
	session, ctx := connectSession(t)
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	if len(res.Tools) != 5 {
		t.Fatalf("工具数 = %d, want 5", len(res.Tools))
	}
	names := []string{}
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	want := []string{"service.list", "service.query", "systemd_dependencies", "systemd_failed", "systemd_timer_next"}
	if !slices.Equal(names, want) {
		t.Errorf("工具集 = %v, want %v", names, want)
	}
}

const failedFixtureOutput = "● nginx.service loaded failed failed A high performance web server\n" +
	"  dnf-makecache.timer loaded failed failed trigger for dnf makecache\n" +
	"tmp.mount loaded failed failed Mounting /tmp...\n" +
	"0 tokens processed.\n"

func TestSystemdFailed_Happy(t *testing.T) {
	capture := fakeSystemctl(t, failedFixtureOutput)
	session, ctx := connectSession(t)

	res, text := callNamedTool(t, session, ctx, "systemd_failed", map[string]any{})
	if res.IsError {
		t.Fatalf("合法调用被误判为错误: %s", text)
	}
	var rows []failedUnitOut
	if err := json.Unmarshal([]byte(text), &rows); err != nil {
		t.Fatalf("回包不是合法 JSON 数组: %v\n%s", err, text)
	}
	if len(rows) != 3 {
		t.Fatalf("元素数 = %d, want 3(垃圾行应被跳过):\n%s", len(rows), text)
	}
	got := []string{rows[0].Unit, rows[1].Unit, rows[2].Unit}
	if !slices.Equal(got, []string{"dnf-makecache.timer", "nginx.service", "tmp.mount"}) {
		t.Errorf("单元序 = %v, want 按名升序(跨类型后缀全集识别)", got)
	}
	if rows[1].LoadState != "loaded" || rows[1].ActiveState != "failed" || rows[1].SubState != "failed" {
		t.Errorf("三态逐字漂移: %+v", rows[1])
	}
	want := []string{"list-units", "--state=failed", "--no-pager", "--no-legend"}
	if argv := readArgv(t, capture); !slices.Equal(argv, want) {
		t.Errorf("argv = %v, want %v", argv, want)
	}
}

func TestSystemdTimerNext_Happy(t *testing.T) {
	capture := fakeSystemctl(t, "Id=dnf-makecache.timer\n"+
		"LoadState=loaded\nActiveState=active\nSubState=waiting\n"+
		"LastTriggerUSec=1767225600000000\n"+
		"NextElapseUSecRealtime=1767236400000000\n"+
		"NextElapseUSecMonotonic=n/a\n")
	session, ctx := connectSession(t)

	res, text := callNamedTool(t, session, ctx, "systemd_timer_next", map[string]any{"name": "dnf-makecache"})
	if res.IsError {
		t.Fatalf("裸名补全 .timer 应合法: %s", text)
	}
	var out timerNextOut
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("回包解析失败: %v\n%s", err, text)
	}
	if out.Unit != "dnf-makecache.timer" || out.ActiveState != "active" {
		t.Errorf("骨架漂移: %+v", out)
	}
	if out.LastTrigger != "2026-01-01T00:00:00Z" || out.NextElapse != "2026-01-01T03:00:00Z" {
		t.Errorf("派生时刻错: last=%q next=%q", out.LastTrigger, out.NextElapse)
	}
	if out.NextElapseUSecMonotonic != "n/a" {
		t.Errorf("monotonic 原值必须照抄: %q", out.NextElapseUSecMonotonic)
	}
	argv := readArgv(t, capture)
	want := append([]string{"show", "dnf-makecache.timer"}, propFlags(systemdTimerProperties)...)
	if !slices.Equal(argv, want) {
		t.Errorf("argv = %v,\nwant %v", argv, want)
	}
}

func TestSystemdTimerNext_RejectsNonTimerAndNotFound(t *testing.T) {
	capture := fakeSystemctl(t, "Id=sshd.service\nLoadState=not-found\n")
	session, ctx := connectSession(t)

	// 显式非 timer 后缀:拒,且零执行。
	res, _ := callNamedTool(t, session, ctx, "systemd_timer_next", map[string]any{"name": "sshd.service"})
	if !res.IsError {
		t.Error("非 timer 单元竟然成功")
	}
	if _, err := os.Stat(capture); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("校验失败仍触发了外部命令: %v", err)
	}
}

func TestSystemdTimerNext_NotFoundUnit(t *testing.T) {
	fakeSystemctl(t, "Id=ghost.timer\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nLastTriggerUSec=0\nNextElapseUSecRealtime=0\nNextElapseUSecMonotonic=0\n")
	session, ctx := connectSession(t)

	res, text := callNamedTool(t, session, ctx, "systemd_timer_next", map[string]any{"name": "ghost.timer"})
	if !res.IsError || !strings.Contains(text, "error: unit ghost.timer not found") {
		t.Fatalf("not-found 应逐字文案拒绝(systemctl show 对未知单元也退 0): %v %s", res.IsError, text)
	}
}

func TestSystemdDependencies_Happy(t *testing.T) {
	capture := fakeSystemctl(t, "Id=sshd.service\nLoadState=loaded\n"+
		"Wants=sshd-keygen.service\nRequires=system.slice\nRequiredBy=\nUpstream=\n"+
		"Before=\nAfter=syslog.target network.target\nConflicts=\nBoundBy=multi-user.target\n")
	session, ctx := connectSession(t)

	res, text := callNamedTool(t, session, ctx, "systemd_dependencies", map[string]any{"name": "sshd.service"})
	if res.IsError {
		t.Fatalf("合法调用被误判: %s", text)
	}
	var out dependenciesOut
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("回包解析失败: %v\n%s", err, text)
	}
	if !slices.Equal(out.After, []string{"network.target", "syslog.target"}) {
		t.Errorf("After 应排序: %v", out.After)
	}
	if !slices.Equal(out.BoundBy, []string{"multi-user.target"}) || len(out.RequiredBy) != 0 {
		t.Errorf("邻接漂移: bound_by=%v required_by=%v", out.BoundBy, out.RequiredBy)
	}
	argv := readArgv(t, capture)
	want := append([]string{"show", "sshd.service"}, propFlags(systemdDepsProperties)...)
	if !slices.Equal(argv, want) {
		t.Errorf("argv = %v,\nwant %v", argv, want)
	}
}

// propFlags 把属性白名单展开为 --property=K 序列(与实现的逐项追加同形)。
func propFlags(props []string) []string {
	out := make([]string, 0, len(props))
	for _, p := range props {
		out = append(out, "--property="+p)
	}
	return out
}

func TestNormalizeUnitTyped(t *testing.T) {
	cases := []struct {
		in, def, want string
		wantErr       bool
	}{
		{"dnf-makecache", "timer", "dnf-makecache.timer", false},
		{"sshd.service", "", "sshd.service", false},
		{"getty@tty1.socket", "timer", "getty@tty1.socket", false},
		{"sshd", "", "", true},         // 依赖视图:裸名必须拒(补后缀即猜)
		{"a/b", "timer", "", true},     // 分隔符
		{"a..b.service", "", "", true}, // 遍历
		{"x.unknown", "", "", true},    // 表外类型后缀
		{"", "timer", "", true},
	}
	for _, tc := range cases {
		got, err := normalizeUnitTyped(tc.in, tc.def)
		if (err != nil) != tc.wantErr {
			t.Errorf("normalizeUnitTyped(%q,%q) err=%v, wantErr=%v", tc.in, tc.def, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("normalizeUnitTyped(%q,%q) = %q, want %q", tc.in, tc.def, got, tc.want)
		}
	}
}

func TestUsecToRFC3339(t *testing.T) {
	cases := map[string]string{
		"1767225600000000":     "2026-01-01T00:00:00Z",
		"0":                    "",
		"n/a":                  "",
		"":                     "",
		"18446744073709551615": "", // systemd infinity 哨兵(超 2100 年)
		"-5":                   "",
	}
	for in, want := range cases {
		if got := usecToRFC3339(in); got != want {
			t.Errorf("usecToRFC3339(%q) = %q, want %q", in, got, want)
		}
	}
}
