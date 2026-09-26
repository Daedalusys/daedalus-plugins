// 条件派生测试:ActiveState → Ready 的映射、只读查询回包的可重放性,以及
// service.query 里 Conditions 真实在场(不是类型上存在、运行时为空)。
package main

import (
	"encoding/json"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/objectmodel"
)

// TestDeriveConditions 钉派生表:active→True、其余一律 False;Reason 取 SubState
// 原文;缺键不造值(空串照常回),转换时刻恒零。
func TestDeriveConditions(t *testing.T) {
	cases := []struct {
		name       string
		props      map[string]string
		wantStatus string
		wantReason string
	}{
		{"active", map[string]string{"ActiveState": "active", "SubState": "running"}, objectmodel.ConditionTrue, "running"},
		{"inactive", map[string]string{"ActiveState": "inactive", "SubState": "dead"}, objectmodel.ConditionFalse, "dead"},
		{"failed", map[string]string{"ActiveState": "failed", "SubState": "failed"}, objectmodel.ConditionFalse, "failed"},
		{"键缺失", map[string]string{}, objectmodel.ConditionFalse, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveConditions(tc.props)
			if len(got) != 1 {
				t.Fatalf("派生条件数 = %d, want 1", len(got))
			}
			c := got[0]
			if c.Type != conditionReady || c.Status != tc.wantStatus || c.Reason != tc.wantReason {
				t.Fatalf("派生结果 = %#v, want type=%s status=%s reason=%q",
					c, conditionReady, tc.wantStatus, tc.wantReason)
			}
			if !c.LastTransitionTime.IsZero() {
				t.Fatalf("只读观测不得伪造转换时刻: %s", c.LastTransitionTime)
			}
		})
	}
}

// TestServiceQuery_CarriesConditions 端到端:夹具报 ActiveState=inactive,断言回包
// Conditions 里有 Ready=False(反造假:只加类型不写入的 handler 必然在此失败)。
// 顺带钉可重放性:同一夹具两次调用,回包字节必须逐字相等。
func TestServiceQuery_CarriesConditions(t *testing.T) {
	fakeSystemctl(t, happyFixtureOutput)
	session, ctx := connectSession(t)

	res, first := callTool(t, session, ctx, map[string]any{"name": "sshd"})
	if res.IsError {
		t.Fatalf("合法查询被误判为错误: %s", first)
	}
	_, second := callTool(t, session, ctx, map[string]any{"name": "sshd"})
	if first != second {
		t.Fatalf("只读查询回包不可重放:\n%s\n%s", first, second)
	}

	var state objectmodel.ServiceState
	if err := json.Unmarshal([]byte(first), &state); err != nil {
		t.Fatalf("回包不是合法 JSON: %v\n%s", err, first)
	}

	obj := state.Object()
	c, ok := obj.Status.GetCondition(conditionReady)
	if !ok {
		t.Fatalf("回包未携带 %s 条件: %s", conditionReady, first)
	}
	if c.Status != objectmodel.ConditionFalse || c.Reason != "dead" {
		t.Fatalf("条件派生与夹具不符: %#v", c)
	}
}
