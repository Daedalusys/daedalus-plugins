// systemd 全景三工具的审计入口(choke point):每个 handle 调 systemd.go 的
// 实现面拿到结局,再经 recordAudit 落恰一条哈希链条目(只读工具,尽力而为,
// 不改工具结果)。与 systemd.go 分文件的动机同因 250 纯 LOC 上限。
package main

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// handleSystemdFailed:无入参,args 记空对象;systemctl 执行故障 error,
// 其余 success。
func handleSystemdFailed(ctx context.Context, _ *mcp.CallToolRequest, _ systemdFailedIn) (*mcp.CallToolResult, any, error) {
	res, outcome, cause := systemdFailedResult(ctx)
	recordAudit("systemd_failed", outcome, map[string]any{}, cause)
	return res, nil, nil
}

// handleSystemdTimerNext:单元名/类型门拒绝 denied;args 记录入参原始 name
// (补全后的规范单元名已在回包内,不重复进链)。
func handleSystemdTimerNext(ctx context.Context, _ *mcp.CallToolRequest, in unitIn) (*mcp.CallToolResult, any, error) {
	res, outcome, cause := systemdTimerNextResult(ctx, in)
	recordAudit("systemd_timer_next", outcome, map[string]any{"name": in.Name}, cause)
	return res, nil, nil
}

// handleSystemdDependencies:单元名校验门拒绝 denied;args 同 timer 视图,
// 只记入参原始 name。
func handleSystemdDependencies(ctx context.Context, _ *mcp.CallToolRequest, in unitIn) (*mcp.CallToolResult, any, error) {
	res, outcome, cause := systemdDependenciesResult(ctx, in)
	recordAudit("systemd_dependencies", outcome, map[string]any{"name": in.Name}, cause)
	return res, nil, nil
}
