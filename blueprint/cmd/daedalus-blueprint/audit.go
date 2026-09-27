// audit.go —— blueprint 的哈希链审计写入面。家族约定:helper 各服务器各持
// 本地副本,不做跨插件共享;落点走 resolveAuditPath(env > 策略 [audit].log_path
// > DefaultLogPath)。六个工具的审计一律经本文件 recordAudit 在各自 handler 的
// choke point 落链——工具逻辑只返回结局 token,不允许在分支里各自开写入口
// (apply/remove 曾有的 legacy writeBlueprintAudit 就是漏记拒绝路径的根源)。
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Daedalusys/daedalus-sdk/audit"
)

// recordAudit 追加一条哈希链审计条目(尽力而为):denied=入参校验 / schema /
// 白名单 / 令牌拒绝,error=渲染或执行故障,其余 success。失败只落一行 stderr
// 警告,不改变工具结果。args 只携带入参摘要,渲染内容与参数值一律不进链。
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
			Identity: blueprintIdentity,
			Tool:     tool,
			Args:     v,
			Outcome:  outcome,
			LogPath:  resolveAuditPath(),
		})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: 审计写入失败: %v\n", blueprintIdentity, err)
	}
}

// shortErrText 截取错误消息,防长 params/子进程输出灌进哈希载荷。
func shortErrText(err error) string {
	const maxRunes = 200
	r := []rune(err.Error())
	if len(r) > maxRunes {
		return string(r[:maxRunes]) + "…"
	}
	return string(r)
}
