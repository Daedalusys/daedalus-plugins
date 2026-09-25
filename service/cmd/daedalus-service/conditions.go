// 条件派生:把 service.query 读到的 systemctl 原文属性抬成对象模型的 Conditions。
//
// Properties 是证据原文,Conditions 是它之上的派生语义层,后者不替代前者。
// 派生是纯本地计算:零新增子进程、零新增白名单键。
package main

import (
	"github.com/Daedalusys/daedalus-sdk/objectmodel"
)

// conditionReady 是 service 资源唯一的派生条件类型:单元是否处于 active。
// LoadState 不派生条件 —— 处理器已在 not-found/masked 时拒绝,走到这里恒为
// loaded,派生出来是一排永真空格。
const conditionReady = "Ready"

// deriveConditions 从观测属性派生条件列表。Reason 取 SubState 原文,让消费方
// 不必回头解析 Properties。
//
// LastTransitionTime 恒留零值:单次只读观测没有"状态何时变的"这个事实来源,
// 编一个观测时刻进去等于伪造转换时间,还会让同一单元的两次查询回包字节不同
// (只读查询必须可重放比对)。观测时刻的正当载体是 state.jsonl 的 observed_at;
// 真实转换时刻的执行面来源是事务 apply。
func deriveConditions(props map[string]string) []objectmodel.Condition {
	status := objectmodel.ConditionFalse
	if props["ActiveState"] == "active" {
		status = objectmodel.ConditionTrue
	}
	return []objectmodel.Condition{{
		Type:   conditionReady,
		Status: status,
		Reason: props["SubState"],
	}}
}
