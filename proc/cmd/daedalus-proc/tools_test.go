// proc 声明面测试:五工具的 schema required 集/中文描述/注解族钉死。
// 与 main_test.go 分文件同家族惯例:250 纯 LOC 上限。
package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestProcToolSpecs(t *testing.T) {
	session, ctx := connectSession(t)
	required := map[string][]string{
		"proc_list":   {},
		"proc_tree":   {},
		"proc_fds":    {"pid"},
		"proc_listen": {},
		"proc_cgroup": {"pid"},
	}
	for name, wantReq := range required {
		tool := findTool(t, session, ctx, name)
		if !strings.Contains(tool.Description, "只读") {
			t.Errorf("%s 描述漂移(中文规格): %q", name, tool.Description)
		}
		schema, ok := tool.InputSchema.(map[string]any)
		if !ok || schema["type"] != "object" {
			t.Fatalf("%s InputSchema 非 object: %#v", name, tool.InputSchema)
		}
		items, _ := schema["required"].([]any)
		if len(items) != len(wantReq) {
			t.Errorf("%s required = %v, want %v", name, items, wantReq)
		}
		var req []string
		for _, item := range items {
			s, _ := item.(string)
			req = append(req, s)
		}
		slices.Sort(req)
		if !slices.Equal(req, wantReq) {
			t.Errorf("%s required = %v, want %v", name, req, wantReq)
		}
		a := tool.Annotations
		if a == nil {
			t.Fatalf("%s 缺 Annotations", name)
		}
		if !a.ReadOnlyHint || !a.IdempotentHint || a.DestructiveHint == nil || *a.DestructiveHint ||
			a.OpenWorldHint == nil || *a.OpenWorldHint {
			t.Errorf("%s 注解集应为 只读/非破坏(显式false)/幂等/封闭世界(显式false): %+v", name, a)
		}
	}
	// 参数枚举钉死:proc_fds.kinds 与 proc_listen.proto 的白名单。
	fdsSchema := findTool(t, session, ctx, "proc_fds").InputSchema.(map[string]any)
	props := fdsSchema["properties"].(map[string]any)
	kinds := props["kinds"].(map[string]any)
	if enums := kinds["items"].(map[string]any)["enum"]; !slicesEqualAny(enums, []any{"file", "socket", "pipe", "other"}) {
		t.Errorf("kinds enum = %v", enums)
	}
	listenSchema := findTool(t, session, ctx, "proc_listen").InputSchema.(map[string]any)
	proto := listenSchema["properties"].(map[string]any)["proto"].(map[string]any)
	if enums := proto["enum"]; !slicesEqualAny(enums, []any{"tcp", "udp"}) {
		t.Errorf("proto enum = %v", enums)
	}
}

func slicesEqualAny(a any, want []any) bool {
	items, ok := a.([]any)
	if !ok || len(items) != len(want) {
		return false
	}
	for i := range items {
		if items[i] != want[i] {
			return false
		}
	}
	return true
}

// findTool 经 tools/list 按名称取回指定工具声明(家族各持本地副本)。
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
