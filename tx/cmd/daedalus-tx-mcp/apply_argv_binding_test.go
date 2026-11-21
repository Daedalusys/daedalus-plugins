package main

// apply_argv_binding_test.go —— 批准指纹与事务两键的结构绑定。
//
// 人批准的是 argv,事务走的是两键(name + desired_state)。两张表各算各的,
// 改一处就会"批准的是一条命令、执行的是另一个动作"。所以两键必须从 argv
// 反解,而不是从请求里抄 —— 这里用逐动词的往返用例把这条绑定钉死。

import (
	"fmt"
	"strings"
	"testing"
)

// serviceVerbCases 是动词表的期望映射:字面量写死,不从生产表派生 —— 用例要能
// 证明契约,而不是证明实现自己跟自己对得上。
var serviceVerbCases = []struct {
	desiredState string
	verb         string
}{
	{desiredState: "started", verb: "start"},
	{desiredState: "stopped", verb: "stop"},
	{desiredState: "restarted", verb: "restart"},
	{desiredState: "enabled", verb: "enable"},
	{desiredState: "disabled", verb: "disable"},
}

// 逐动词:期望状态→动词、动词→期望状态、argv→两键 三条路必须互相闭合。
// 任何一处映射被改坏,这个用例都必须变红。
func TestServiceVerbTableRoundTrip(t *testing.T) {
	for _, c := range serviceVerbCases {
		t.Run(c.desiredState, func(t *testing.T) {
			verb, ok := verbForDesiredState(c.desiredState)
			if !ok || verb != c.verb {
				t.Fatalf("期望状态 %q 应翻成动词 %q, 实际 %q(存在=%v)", c.desiredState, c.verb, verb, ok)
			}
			back, ok := desiredStateForVerb(c.verb)
			if !ok || back != c.desiredState {
				t.Fatalf("动词 %q 应翻回期望状态 %q, 实际 %q(存在=%v)", c.verb, c.desiredState, back, ok)
			}

			view, serr := buildPreview(c.desiredState, "demo.service", domainUser, defaultConfig(),
				observation{enabled: true, running: false, known: true})
			if serr != nil {
				t.Fatalf("判定失败: %+v", serr)
			}
			want := []string{"systemctl", "--user", c.verb, "demo.service"}
			if !equalStrings(view.Argv, want) {
				t.Fatalf("argv = %v, 期望 %v", view.Argv, want)
			}

			intent, ok := serviceSetIntentFromArgv(view.Argv)
			if !ok {
				t.Fatalf("argv %v 反解不出两键", view.Argv)
			}
			if intent.unit != "demo.service" || intent.desiredState != c.desiredState {
				t.Fatalf("argv 反解 = %+v, 期望 unit=demo.service desired_state=%s", intent, c.desiredState)
			}
		})
	}
}

// 事务的两键必须来自被批准的 argv:把 view 里的两键改成别的,propose 的 args
// 仍必须是 argv 派生的那一份 —— 这就是"批准什么就执行什么"的绑定。
func TestTransactionKeysAreDerivedFromArgv(t *testing.T) {
	for _, c := range serviceVerbCases {
		t.Run(c.desiredState, func(t *testing.T) {
			f := newApplyFixture(t, obsEnabledStopped)
			view, serr := buildPreview(c.desiredState, "demo.service", domainUser, defaultConfig(),
				observation{enabled: true, running: false, known: true})
			if serr != nil {
				t.Fatalf("判定失败: %+v", serr)
			}
			// 模拟"两键与 argv 不同源":请求侧被改成了别的动作。
			view.Name = "tampered.service"
			view.DesiredState = "tampered"

			if _, rej := runTransaction(view, map[string]any{}); rej != nil {
				t.Fatalf("事务应执行: %+v", rej)
			}
			propose := ""
			for _, call := range readCalls(t, f.calls) {
				if strings.HasPrefix(call, "propose ") {
					propose = call
				}
			}
			if propose == "" {
				t.Fatalf("未见 propose 调用: %v", readCalls(t, f.calls))
			}
			want := fmt.Sprintf(`{"name":"demo.service","desired_state":%q}`, c.desiredState)
			if !strings.Contains(propose, want) {
				t.Fatalf("propose args = %s, 期望含 %s", propose, want)
			}
			if strings.Contains(propose, "tampered") {
				t.Fatalf("propose args 用了请求里的字面量,没有绑定 argv: %s", propose)
			}
		})
	}
}

// 反解不出两键的 argv 一律拒绝执行:绝不退回请求里的期望状态去猜。
func TestTransactionRejectsArgvWithoutTwoKeys(t *testing.T) {
	f := newApplyFixture(t, obsEnabledStopped)
	view, serr := buildPreview("started", "demo.service", domainUser, defaultConfig(),
		observation{enabled: true, running: false, known: true})
	if serr != nil {
		t.Fatalf("判定失败: %+v", serr)
	}
	view.Argv = []string{"systemctl", "--user", "reload", "demo.service"}

	if _, rej := runTransaction(view, map[string]any{}); rej == nil {
		t.Fatal("反解不出两键的 argv 必须被拒")
	}
	requireNoChanges(t, readCalls(t, f.calls))
}
