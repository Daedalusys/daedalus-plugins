// avc_exec 收敛 ausearch 专属退出码语义:handleExecError 把 execError envelope 翻译为
// 可读 note,区分合法空集(<no matches>)/ 审计日志不可读 / 审计配置不可读。
// ⚠ 依赖 ausearch 的 stderr 文案特征,克隆 smart / gpu 等插件时**勿带走本文件**——
// 可移植 runner 在 avc.go 的"可移植 runner(core)"块(execError / isMissingBinary /
// execHelper / mergeNotes);本文件判定对其它 CLI 形态不适用(如 journalctl 的
// rc=0+stdout "<no entries>" 或 rpm 的 rc=1 "no installed packages" 均需重写)。
package main

import (
	"errors"
	"strings"
)

// isAusearchNoMatch 识别 ausearch rc=1 + stderr 含 "<no matches>" 的合法
// 空集信号。本机实测 ausearch rc=1 时 "<no matches>" 写到 stderr(--input <empty>
// -m 形态亦同),按异常 envelope 收 stderr。
func isAusearchNoMatch(err error) bool {
	if err == nil {
		return false
	}
	var ee *execError
	if !errors.As(err, &ee) {
		return false
	}
	return ee.Code == 1 && strings.Contains(ee.Stderr, "<no matches>")
}

// isAuditLogUnavailable 识别 ausearch rc=1 + stderr 含 "Error opening
// /var/log/audit/audit.log" 或 "Error opening config file" 的审计日志不可读
// 信号。两种都是 auditd 未启用 / 配置无访问权限的常见形态。
func isAuditLogUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var ee *execError
	if !errors.As(err, &ee) {
		return false
	}
	if ee.Code != 1 {
		return false
	}
	return strings.Contains(ee.Stderr, "Error opening /var/log/audit") ||
		strings.Contains(ee.Stderr, "Error opening config file")
}

// handleExecError 收敛 ausearch runner 错误的语义分类:binary 缺失、rc=1+<no
// matches>、rc=1+审计日志不可读均非 fatal,降级为 note;rc≥2 或非 *execError
// 视为真故障,fatal=true 上抛。
//
// 判定顺序敏感:`isAuditLogUnavailable` 优先于 `isAusearchNoMatch`——auditd 未
// 启用时 stderr 可能同时含 "Error opening ... audit.log" 与 "<no matches>",
// 此种场景掩盖 auditd 提示会让运维错失最关键的可行动线索。
//
// 注意:此语义仅适用于 ausearch 作为**主数据源**的 Recent / Summary / Explain
// 第 1 段(其退出码语义应一致上抛);Explain 第 2、3 段(audit2why / audit2allow)
// 是"可选解释后端",各自按 per-stage 策略降级——见 Explain 内联注释,不调用本函数
// 的 fatal 分支直接上抛,而是改写 note 后继续后续阶段。
//
// 调用方约定:err != nil 且 !fatal 时不得把结果宣称为"干净 / 合法空集"——
// rc=1 已声明某种失败;run 收集到的行后续要按业务解释继续解析。
func handleExecError(err error) (note string, fatal bool) {
	if err == nil {
		return "", false
	}
	if isMissingBinary(err) {
		return "CLI 不可用: " + err.Error(), false
	}
	var ee *execError
	if !errors.As(err, &ee) || ee.Code >= 2 {
		return "", true
	}
	// 顺序:auditd 未启用优先于无匹配(同现时掩盖更具运维价值的提示)
	if isAuditLogUnavailable(err) {
		return "auditd 未启用或审计日志不可访问: " + strings.TrimSpace(ee.Stderr), false
	}
	if isAusearchNoMatch(err) {
		return "无匹配 AVC 事件", false
	}
	return "ausearch 报告差异(退出码 1),已按 stdout 解析", false
}
