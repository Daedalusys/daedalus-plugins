// audit.go —— tx_apply 的哈希链审计写入面:落点解析与 recordAudit。
// 家族约定:helper 各服务器各持本地副本,不做跨插件共享。
//
// 写通道的每次尝试(执行 / 幂等 / 拒绝 / 失败)都要留一条带 tier 的证据;
// 审计不可写时只告警不改变工具结果 —— 这与家族其余服务器一致,证据缺失由运维
// 从 stderr 与 rx 的写入失败上发现,而不是让写通道在审计盘满时静默罢工。
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Daedalusys/daedalus-sdk/audit"
)

// policyAuditLogPath 是启动期 loadRuntime 捕获的策略 [audit].log_path。
// 同一身份分裂写进多条链会让 daedalus-audit verify 必判断链,故全插件统一解析链。
var policyAuditLogPath string

// resolveAuditPath 解析审计日志落点:DAEDALUS_AUDIT_LOG_PATH 环境变量优先,
// 其次策略 [audit].log_path,皆空则交给 LogAudit 的默认路径。
func resolveAuditPath() string {
	if v := os.Getenv(audit.EnvLogPath); v != "" {
		return v
	}
	return policyAuditLogPath
}

// recordAudit 追加一条哈希链条目。args 只放判定与寻址字段:条子明文与 argv
// 都不进链(可复现的判据是 tier / grant_id / tx_id / decision_path)。
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

// shortErrText 截断错误消息,防超长 CLI 输出灌进哈希载荷。
func shortErrText(err error) string {
	if err == nil {
		return ""
	}
	return truncateRunes(err.Error(), 240)
}

// truncateRunes 按字符(不是字节)截断,避免切断多字节字符产出非法 UTF-8。
func truncateRunes(s string, maxRunes int) string {
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes]) + "…"
}
