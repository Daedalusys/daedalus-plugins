// audit.go —— service 的哈希链审计写入面。家族约定:helper 各服务器各持
// 本地副本,不做跨插件共享;本插件不加载 policy.toml,故不传 LogPath,由
// LogAudit 回退 DefaultLogPath()(与 daedalus-shell 解析链一致)。
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Daedalusys/daedalus-sdk/audit"
)

// recordAudit 追加一条哈希链审计条目(只读工具,尽力而为):denied=入参
// 校验拒绝,error=systemctl 执行失败或单元 not-found/masked。失败只落一行
// stderr 警告,不改变工具结果。
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
		})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: 审计写入失败: %v\n", serverName, err)
	}
}

// shortErrText 截取错误消息,防 systemctl 长 stderr 灌进哈希载荷。
func shortErrText(err error) string {
	const maxRunes = 200
	r := []rune(err.Error())
	if len(r) > maxRunes {
		return string(r[:maxRunes]) + "…"
	}
	return string(r)
}
