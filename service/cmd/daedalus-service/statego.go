// 状态记忆写入面:每次成功的 service.query / service.list 之后,向 internal/state
// 追加一条 Kind="service" 的观测条目;与 main.go / list.go 同包拆文件的动机是
// 250 纯 LOC 上限。
//
// 三条语义:1) 只在成功路径写(state 记"曾观测到什么",不记"曾尝试过什么");
// 2) best-effort:写失败只落 stderr,不改返回值、不 panic、不产生审计事件;
// 3) 路径零字面量:落位交给 state.Log → internal/dirs,本文件不出现路径常量。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Daedalusys/daedalus-sdk/objectmodel"
	"github.com/Daedalusys/daedalus-sdk/state"
)

// stateLog 是测试注入缝:生产态恒指向 state.Log,测试覆写为返回 error 的桩
// 即可验证 best-effort 语义。
var stateLog = state.Log

// recordServiceState 追加一条服务观测:payload 就是工具回包序列化的同一份
// JSON(objectmodel.ServiceState 或 []ServiceState,含 Properties 全量,不得
// 降级成 3 字段 Resource 声明)。任何失败都收敛为一行 stderr,
// 调用方(工具结果)不受影响。
func recordServiceState(name string, payload any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// 与 jsonResult 同规矩:不做 HTML 转义,载荷里的 < > & 原样落盘。
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		fmt.Fprintf(os.Stderr, "%s: 状态写入失败: %v\n", serverName, err)
		return
	}
	entry := state.StateEntry{
		Kind:       string(objectmodel.KindService),
		Name:       name,
		ObservedAt: time.Now().UTC(),
		// Encode 追加的行尾换行不属于 JSON 值,剥掉再交 RawMessage。
		Payload: json.RawMessage(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))),
	}
	if err := stateLog(entry); err != nil {
		fmt.Fprintf(os.Stderr, "%s: 状态写入失败: %v\n", serverName, err)
	}
}
