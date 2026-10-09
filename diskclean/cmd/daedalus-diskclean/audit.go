// audit.go —— diskclean 的哈希链审计写入面:落点解析与 recordAudit。
// 家族约定:helper 各服务器各持本地副本,不做跨插件共享。
//
// diskclean 的 4 个工具中,disk_scan / disk_estimate / disk_explain 是只读
// (审计尽力而为:写入失败只留 stderr 线索,不改变工具结果);
// disk_clean 是写型,审计 outcome 必须如实记录 success / denied / error,
// args 仅带 plan_id 与 tx_id(路径列表与 confirm_token 严禁进链)。
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Daedalusys/daedalus-sdk/audit"
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

// recordAudit 追加一条哈希链审计条目;args 只携带工具入参字段,
// denied/error 附带截断后的 error 摘要,失败恒落一行 stderr 警告。
// confirm_token 与路径列表严禁进 args(load-bearing 安全约束)。
func recordAudit(tool, outcome string, args map[string]any, cause error) {
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
}

// shortErrText 截取错误消息,防超长 I/O 输出灌进哈希载荷。
func shortErrText(err error) string {
	const maxRunes = 200
	r := []rune(err.Error())
	if len(r) > maxRunes {
		return string(r[:maxRunes]) + "…"
	}
	return string(r)
}
