package main

// tools.go —— 共享注解助手。
//
// 工具分文件实现:
//   - list_tools.go  : blueprint_list / blueprint_inspect(todo 17)
//   - render_tool.go : blueprint_render(todo 18)
//   - apply_tool.go  : blueprint_apply(todo 19)
//   - status_tool.go : blueprint_status / blueprint_remove(todo 20)
//
// 本文件只承载跨工具共享的注解助手(readOnly/destructive annotations)。

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// readOnlyAnnotations 返回只读工具的注解(ReadOnlyHint=true,Idempotent=true)。
// 与 daedalus-pkg 的 nonDestructive 取址用法一致(SDK DestructiveHint 为 *bool)。
func readOnlyAnnotations() *mcp.ToolAnnotations {
	nonDestructive := false
	closedWorld := false
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}
}

// destructiveAnnotations 返回写型工具注解(ReadOnly=false,Idempotent=false)。
func destructiveAnnotations() *mcp.ToolAnnotations {
	destructive := true
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		DestructiveHint: &destructive,
		IdempotentHint:  false,
	}
}
