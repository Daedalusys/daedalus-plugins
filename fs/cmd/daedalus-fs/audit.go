// audit.go —— fs 的哈希链审计写入面:落点解析、recordAudit 与变更型工具
// 的 fail-closed 结果。家族约定:helper 各服务器各持本地副本,不做跨插件共享。
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Daedalusys/daedalus-sdk/audit"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// policyAuditLogPath 是启动期 applyPolicy 捕获的策略 [audit].log_path。
// 同一身份分裂写进多条链会让 daedalus-audit verify 必判断链,故全插件统一解析链。
var policyAuditLogPath string

// resolveAuditPath 解析审计日志落点:DAEDALUS_AUDIT_LOG_PATH 环境变量优先,
// 其次策略 [audit].log_path,皆空则由 LogAudit 回退 DefaultLogPath()
// (与 daedalus-shell 的 auditPath 同一链序)。
func resolveAuditPath() string {
	if v := os.Getenv(audit.EnvLogPath); v != "" {
		return v
	}
	return policyAuditLogPath
}

// recordAudit 追加一条哈希链审计条目并返回写入错误;失败恒先落一行 stderr
// 警告(断链事故必须留痕)。读型工具忽略返回值(尽力而为),写型工具据此
// fail-closed。args 只携带工具入参字段,文件内容一律不进链。
func recordAudit(tool, outcome string, args map[string]any, cause error) error {
	if cause != nil {
		args["error"] = shortErrText(cause)
	}
	var v *audit.Value
	data, err := json.Marshal(args)
	if err == nil {
		v, err = audit.ParseValue(string(data))
	}
	if err == nil {
		_, err = audit.LogAudit(audit.Entry{
			Identity: serverName,
			Tool:     tool,
			Args:     v,
			Outcome:  outcome,
			LogPath:  resolveAuditPath(),
		})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: 审计写入失败: %v\n", serverName, err)
	}
	return err
}

// auditBrokenResult 变更型工具 fail-closed 统一错误结果:审计证据未落链时
// 操作效果无法向合规侧自证,一律按"结果未知、禁止盲目重试"上报。
func auditBrokenResult(op string, cause error) *mcp.CallToolResult {
	return toolError(fmt.Errorf(
		"%s 的审计证据未能写入哈希链(%v):该操作的实际结果未经合规确证、可能未知,禁止盲目重试", op, cause))
}

// shortErrText 截取错误消息,防长子进程/IO 输出灌进哈希载荷。
func shortErrText(err error) string {
	const maxRunes = 200
	r := []rune(err.Error())
	if len(r) > maxRunes {
		return string(r[:maxRunes]) + "…"
	}
	return string(r)
}
