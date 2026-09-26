// trace 声明面测试:握手工具集的 schema/描述/注解钉死与错误文案形态。
// 与 main_test.go 分文件同家族惯例:250 纯 LOC 上限。
package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestTraceToolSpecs 声明面:四工具名称/中文描述/required 集与注解族钉死。
func TestTraceToolSpecs(t *testing.T) {
	fixtureLog(t)
	session, ctx := connectSession(t)

	required := map[string][]string{
		"trace_session": {"session_id"},
		"trace_tool":    {"tool_name"},
		"trace_tx":      {"tx_id"},
		"trace_summary": {},
	}
	for name, wantReq := range required {
		list := findTool(t, session, ctx, name)
		if !strings.Contains(list.Description, "只读") {
			t.Errorf("%s 描述漂移(中文规格): %q", name, list.Description)
		}
		schema, ok := list.InputSchema.(map[string]any)
		if !ok || schema["type"] != "object" {
			t.Fatalf("%s InputSchema 非 object: %#v", name, list.InputSchema)
		}
		var req []string
		items, _ := schema["required"].([]any)
		if len(items) != len(wantReq) {
			t.Errorf("%s required = %v, want %v", name, items, wantReq)
		}
		for _, item := range items {
			s, _ := item.(string)
			req = append(req, s)
		}
		slices.Sort(req)
		if !slices.Equal(req, wantReq) {
			t.Errorf("%s required = %v, want %v", name, req, wantReq)
		}
		a := list.Annotations
		if a == nil {
			t.Fatalf("%s 缺 Annotations", name)
		}
		if !a.ReadOnlyHint || !a.IdempotentHint || a.DestructiveHint == nil || *a.DestructiveHint ||
			a.OpenWorldHint == nil || *a.OpenWorldHint {
			t.Errorf("%s 注解集应为 只读/非破坏(显式false)/幂等/封闭世界(显式false): %+v", name, a)
		}
	}
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
