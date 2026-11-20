// preview.go —— tx_preview 的判定面:入参校验、作用域寻址、属性快照与 argv 组装。
//
// 本文件只做只读观测(service-observe)与纯判定(autonomy.Classify),不执行任何
// 变更命令 —— 同一输入永远得到同一档位,审计里的 tier 才可复现。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
)

const (
	kindService       = "service"
	adapterServiceSet = "service.set"
	// 域只取这两个字面值:Classify 只认字面 "user",其余(含空串、大小写变体)
	// 一律按最严处理,所以构造 Attributes 时必须显式赋值。
	domainUser   = "user"
	domainSystem = "system"
)

// unitNamePattern 与 core 的 service.set 名称门逐字一致:字母数字下划线点 @ 连字符。
// 首字符排除 '-' —— 前导中划线会被 systemctl 当选项解析(argv 注入面在源头即不存在)。
var unitNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@][A-Za-z0-9_.@-]*$`)

// desiredStateVerbs 是 v1 封闭动词集到 systemctl 动词的映射。
// reload 被 service.set 适配器逐字拒绝,故不在表内;表外动作"不认识就不做"。
var desiredStateVerbs = map[string]string{
	"started":   "start",
	"stopped":   "stop",
	"restarted": "restart",
	"enabled":   "enable",
	"disabled":  "disable",
}

type previewIn struct {
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	DesiredState string `json:"desired_state"`
}

// previewAttributes 是判定时实际喂给 Classify 的属性快照,原样回给客户端,
// 让"为什么是这个档位"可以离线复核。
type previewAttributes struct {
	Domain   string `json:"domain"`
	HighRisk bool   `json:"high_risk"`
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Known    bool   `json:"known"`
}

type previewView struct {
	Kind          string            `json:"kind"`
	Name          string            `json:"name"`
	DesiredState  string            `json:"desired_state"`
	Adapter       string            `json:"adapter"`
	Scope         string            `json:"scope"`
	Tier          string            `json:"tier"`
	Reason        string            `json:"reason"`
	RequiredScope []string          `json:"required_scope"`
	Argv          []string          `json:"argv"`
	Attributes    previewAttributes `json:"attributes"`
}

// structuredError 是拒绝面的机器可读形态:客户端按 error 分支,不靠字符串匹配。
type structuredError struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// observation 是档位判定用得上的三个属性;known=false 表示查不到,按最严处理。
type observation struct {
	enabled bool
	running bool
	known   bool
}

// preparePreview 校验入参并原样回显单元名。kind 与动词集都是封闭的:表外一律拒绝。
func preparePreview(in previewIn) (unit string, serr *structuredError) {
	if in.Kind != kindService {
		return "", &structuredError{
			Error:  "unsupported_kind",
			Detail: fmt.Sprintf("v1 只接 kind=service,收到 %q", in.Kind),
		}
	}
	if _, ok := desiredStateVerbs[in.DesiredState]; !ok {
		return "", &structuredError{
			Error:  "unsupported_desired_state",
			Detail: fmt.Sprintf("v1 动词集为 started/stopped/restarted/enabled/disabled,收到 %q", in.DesiredState),
		}
	}
	unit, err := normalizeUnitName(in.Name)
	if err != nil {
		return "", &structuredError{Error: "invalid_name", Detail: err.Error()}
	}
	return unit, nil
}

// buildPreview 是纯判定:作用域与属性都由调用方给出。domain 是 Attributes.Domain
// 的唯一赋值点 —— 必须显式传 user/system,零值会让所有对象静默降级到第三档。
func buildPreview(desiredState, unit, domain string, cfg *autonomy.Config, obs observation) (previewView, *structuredError) {
	verb, ok := desiredStateVerbs[desiredState]
	if !ok {
		return previewView{}, &structuredError{
			Error:  "unsupported_desired_state",
			Detail: fmt.Sprintf("v1 动词集为 started/stopped/restarted/enabled/disabled,收到 %q", desiredState),
		}
	}

	scope := autonomy.Scope{Runtime: "systemd", Domain: domain, Action: verb, Target: unit}
	attrs := autonomy.Attributes{
		Domain:  domain,
		Enabled: obs.enabled,
		Running: obs.running,
		Known:   obs.known,
	}
	decision := cfg.Classify(scope, attrs)

	required := decision.RequiredScope
	if required == nil {
		required = []string{}
	}
	return previewView{
		Kind:          kindService,
		Name:          unit,
		DesiredState:  desiredState,
		Adapter:       adapterServiceSet,
		Scope:         scope.String(),
		Tier:          string(decision.Tier),
		Reason:        decision.Reason,
		RequiredScope: required,
		Argv:          systemctlArgv(domain, verb, unit),
		Attributes: previewAttributes{
			Domain: domain,
			// deny 命中(危险名单或高危属性)就是"机器自动查得的高危",如实回填。
			HighRisk: decision.Reason == autonomy.ReasonDeny,
			Enabled:  obs.enabled,
			Running:  obs.running,
			Known:    obs.known,
		},
	}, nil
}

// systemctlArgv 组装将执行的 argv。user 域恒带 --user(与 service.set 适配器同域);
// system 域的命令只出现在第三档提案里给人看,去掉 --user 才是可直接执行的形态。
func systemctlArgv(domain, verb, unit string) []string {
	if domain == domainUser {
		return []string{"systemctl", "--user", verb, unit}
	}
	return []string{"systemctl", verb, unit}
}

// normalizeUnitName 是单元名门:只接受 .service 结尾的名字,原样回显。
//
// 不做任何隐式改写:把 foo.timer 补成 foo.timer.service 会造成"观测 A、实际改 B";
// 裸名补 .service 同样是一次改写,而观测命令(service-observe)只认 .service 字面量。
// 三者(观测、propose、systemctl)必须吃同一个字符串,所以补后缀这件事交给调用方。
func normalizeUnitName(name string) (string, error) {
	if name == "" || !unitNamePattern.MatchString(name) {
		return "", fmt.Errorf("单元名非法: %q(仅允许字母数字与 _ . @ -)", name)
	}
	if !strings.HasSuffix(name, ".service") {
		return "", fmt.Errorf("v1 只接受 .service 单元名: %q(不做隐式补后缀)", name)
	}
	return name, nil
}

// observeUnit 调 daedalus-tx service-observe(只读,零副作用)。进程起不来、非零
// 退出、JSON 坏或字段不全都折成 known=false —— 半份观测会被当成完整观测用,
// 缺一个键就可能把"没查到"读成"未启用"。
func observeUnit(unit string) observation {
	stdout, stderrText, rc, err := runTx("service-observe", "--unit", unit)
	if err != nil || rc != 0 {
		fmt.Fprintf(os.Stderr, "%s: service-observe %s 失败(按查不到处理): rc=%d err=%v stderr=%s\n",
			serverName, unit, rc, err, strings.TrimSpace(stderrText))
		return observation{}
	}
	// 指针字段用来区分"没有这个键"与"值为 false":缺键即半份观测。
	var wire struct {
		Enabled *bool `json:"enabled"`
		Running *bool `json:"running"`
		Known   *bool `json:"known"`
	}
	if err := json.Unmarshal([]byte(stdout), &wire); err != nil {
		fmt.Fprintf(os.Stderr, "%s: service-observe 输出无法解析(按查不到处理): %v\n", serverName, err)
		return observation{}
	}
	if wire.Known == nil || !*wire.Known || wire.Enabled == nil || wire.Running == nil {
		return observation{}
	}
	return observation{enabled: *wire.Enabled, running: *wire.Running, known: true}
}
