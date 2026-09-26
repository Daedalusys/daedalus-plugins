// audit.go —— proc 的哈希链审计写入面。家族约定:helper 各服务器各持
// 本地副本,不做跨插件共享;本插件不加载 policy.toml,不传 LogPath →
// LogAudit 回退 DefaultLogPath()(env → /var/log/daedalus),与 daedalus-shell
// 的解析链一致。
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Daedalusys/daedalus-sdk/audit"
)

// recordAudit 追加一条哈希链审计条目(只读工具,尽力而为):入参校验
// 拒绝 denied,/proc 读取故障 error,其余 success。失败只落一行 stderr
// 警告,不改变工具结果。
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

// putOpt 仅记录客户端显式提供的可选参数(nil 表示未提供,不进链)。
func putOpt[T any](args map[string]any, key string, v *T) {
	if v != nil {
		args[key] = *v
	}
}

// shortErrText 截取错误消息,防超长 /proc 内容灌进哈希载荷。
func shortErrText(err error) string {
	const maxRunes = 200
	r := []rune(err.Error())
	if len(r) > maxRunes {
		return string(r[:maxRunes]) + "…"
	}
	return string(r)
}
