package main

// tools.go —— 跨工具共享的注解助手。工具分文件实现:list_tools.go(list/inspect)、
// render_tool.go(render)、apply_tool.go(apply)、status_tool.go(status/remove)。

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// readOnlyAnnotations 返回只读工具的注解。
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

// destructiveAnnotations 返回写型工具注解。
func destructiveAnnotations() *mcp.ToolAnnotations {
	destructive := true
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		DestructiveHint: &destructive,
		IdempotentHint:  false,
	}
}
