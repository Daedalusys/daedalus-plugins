// systemd 全景视图三工具(daedalus-plugins#12)的实现面:失败单元 /
// timer 下次触发 / 依赖图。工具注册仍在 main.go newServer 里一行调用
// registerSystemdTools;本文件与 main.go / list.go 同包,拆文件动机是
// 250 纯 LOC 上限。
//
// 职责切分(issue 框架验证点的答复):systemd_* 是"systemd 全景视图"
// (跨单元类型、无 objectmodel 载荷);service.query/service.list 是
// "service kind 专属观测"(ServiceState + state 记忆)。三个新工具都是
// 全局/跨类型视图,**不写 state.jsonl**(state 记忆语义钉在单资源观测)。
//
// 安全边界与既有两工具同源:单元名先经白名单字符类 + 遍历检查 + 类型后缀
// 全集核验(argv 构造前 fail-closed 拒绝),再 os/exec argv 直发 systemctl,
// 绝不经过 sh -c;属性一律 --property 白名单逐项,不做任意属性透传。
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// unitTypeSuffixes 是单元类型后缀全集(systemd 原生 unit types)。三个新工具
// 的单元名核验与 list-units 行解析都以它为准;service.list/service.query 的
// ".service 专属"语义不受影响。
var unitTypeSuffixes = map[string]bool{
	"automount": true, "device": true, "mount": true, "path": true,
	"scope": true, "service": true, "slice": true, "socket": true,
	"swap": true, "target": true, "timer": true,
}

// systemdFailedIn:systemd_failed 无参数(空对象 schema)。
type systemdFailedIn struct{}

// unitIn 是 systemd_timer_next / systemd_dependencies 的共用入参形态。
type unitIn struct {
	Name string `json:"name"`
}

// failedUnitOut 是失败单元一行;三态键名与 ServiceState.Properties 的
// systemctl 原生键对齐,但单元名不再限定 .service 后缀。
type failedUnitOut struct {
	Unit        string `json:"unit"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
}

// timerNextOut 是 timer 观测载荷:USec 原值照抄 systemctl(KEY=VALUE 原文),
// 派生字段给出 UTC RFC3339(仅 realtime 可用时;monotonic 原样保留不换算,
// 其基准是 CLOCK_MONOTONIC,换成墙钟即造假)。
type timerNextOut struct {
	Unit                    string `json:"unit"`
	LoadState               string `json:"load_state"`
	ActiveState             string `json:"active_state"`
	SubState                string `json:"sub_state"`
	LastTriggerUSec         string `json:"last_trigger_usec"`
	LastTrigger             string `json:"last_trigger,omitempty"`
	NextElapseUSecRealtime  string `json:"next_elapse_usec_realtime"`
	NextElapse              string `json:"next_elapse,omitempty"`
	NextElapseUSecMonotonic string `json:"next_elapse_usec_monotonic"`
}

// dependenciesOut 是依赖图一层邻接(直接 Wants/Requires/…,不做 --transitive
// 递归:全图遍历是 systemd2 视图的事,本工具钉"直接依赖")。
type dependenciesOut struct {
	Unit       string   `json:"unit"`
	LoadState  string   `json:"load_state"`
	Wants      []string `json:"wants"`
	Requires   []string `json:"requires"`
	Upstream   []string `json:"upstream"`
	RequiredBy []string `json:"required_by"`
	Before     []string `json:"before"`
	After      []string `json:"after"`
	Conflicts  []string `json:"conflicts"`
	BoundBy    []string `json:"bound_by"`
}

// systemdTimerProperties / systemdDepsProperties 是两处 --property 白名单。
var systemdTimerProperties = []string{
	"Id", "LoadState", "ActiveState", "SubState",
	"LastTriggerUSec", "NextElapseUSecRealtime", "NextElapseUSecMonotonic",
}
var systemdDepsProperties = []string{
	"Id", "LoadState", "Wants", "Requires", "RequiredBy",
	"Upstream", "Before", "After", "Conflicts", "BoundBy",
}

// registerSystemdTools 挂三个只读工具;注解与既有两工具同族(只读/非破坏/
// 幂等/封闭世界)。描述形态对齐 service.query(中文:做什么/参数/返回)。
func registerSystemdTools(server *mcp.Server, annotations *mcp.ToolAnnotations) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "systemd_failed",
		Description: "只读列出启动失败的 systemd 单元(全部类型,不限 service)。\n\n通过 `systemctl list-units --state=failed --no-pager --no-legend`\n获取,逐行解析 UNIT/LOAD/ACTIVE/SUB。\n\n参数：\n    无。\n\n返回：\n    按单元名升序的失败单元数组(unit/load_state/active_state/sub_state)。",
		InputSchema: &jsonschema.Schema{Type: "object"},
		Annotations: annotations,
	}, handleSystemdFailed)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "systemd_timer_next",
		Description: "只读查询 timer 单元的触发时刻。\n\n通过 `systemctl show <unit>.timer --property=...`(属性白名单:\nLastTriggerUSec/NextElapseUSecRealtime/NextElapseUSecMonotonic)获取。\nUSec 为 systemctl 原值;last_trigger/next_elapse 为 UTC RFC3339 派生值\n(仅 realtime 可用时给出)。\n\n参数：\n    name: timer 单元名,省略后缀时自动补 .timer(例如 'dnf-makecache')。\n\n返回：\n    类型化 timer 观测对象(unit/三态/usec 原值/派生时刻)。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"name": {Type: "string", Description: "timer 单元名,省略后缀时自动补 .timer(例如 'dnf-makecache')。"},
			},
			Required: []string{"name"},
		},
		Annotations: annotations,
	}, handleSystemdTimerNext)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "systemd_dependencies",
		Description: "只读查询单元的直接依赖图。\n\n通过 `systemctl show <unit> --property=...`(属性白名单:\nWants/Requires/RequiredBy/Upstream/Before/After/Conflicts/BoundBy)\n获取一层邻接;不展开 --transitive。\n\n参数：\n    name: 单元名,必须带类型后缀(例如 'sshd.service')。\n\n返回：\n    单元 + LoadState + 八类依赖列表(各自按名称升序)。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"name": {Type: "string", Description: "单元名,必须带类型后缀(例如 'sshd.service')。"},
			},
			Required: []string{"name"},
		},
		Annotations: annotations,
	}, handleSystemdDependencies)
}

func handleSystemdFailed(ctx context.Context, _ *mcp.CallToolRequest, _ systemdFailedIn) (*mcp.CallToolResult, any, error) {
	out, err := runSystemctl(ctx, "list-units", "--state=failed", "--no-pager", "--no-legend")
	if err != nil {
		return raisedError("systemd_failed", err), nil, nil
	}
	rows := parseUnitRows(out)
	slices.SortFunc(rows, func(a, b failedUnitOut) int { return strings.Compare(a.Unit, b.Unit) })
	return jsonResult(rows), nil, nil
}

func handleSystemdTimerNext(ctx context.Context, _ *mcp.CallToolRequest, in unitIn) (*mcp.CallToolResult, any, error) {
	const toolName = "systemd_timer_next"
	unit, err := normalizeUnitTyped(in.Name, "timer")
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	// 视图专属门:显式给了非 .timer 后缀(属性表会全空,查询必然无意义)→ 拒。
	if !strings.HasSuffix(unit, ".timer") {
		return raisedError(toolName, fmt.Errorf("systemd_timer_next 仅接受 timer 单元: %q", unit)), nil, nil
	}
	props, err := runSystemctlShowProps(ctx, unit, systemdTimerProperties)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	if notFound := unitNotFoundResult(unit, props); notFound != nil {
		return notFound, nil, nil
	}
	last := props["LastTriggerUSec"]
	next := props["NextElapseUSecRealtime"]
	return jsonResult(timerNextOut{
		Unit: unit, LoadState: props["LoadState"], ActiveState: props["ActiveState"],
		SubState:        props["SubState"],
		LastTriggerUSec: last, LastTrigger: usecToRFC3339(last),
		NextElapseUSecRealtime: next, NextElapse: usecToRFC3339(next),
		NextElapseUSecMonotonic: props["NextElapseUSecMonotonic"],
	}), nil, nil
}

func handleSystemdDependencies(ctx context.Context, _ *mcp.CallToolRequest, in unitIn) (*mcp.CallToolResult, any, error) {
	const toolName = "systemd_dependencies"
	unit, err := normalizeUnitTyped(in.Name, "")
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	props, err := runSystemctlShowProps(ctx, unit, systemdDepsProperties)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	if notFound := unitNotFoundResult(unit, props); notFound != nil {
		return notFound, nil, nil
	}
	deps := dependenciesOut{Unit: unit, LoadState: props["LoadState"]}
	for _, p := range []struct {
		prop string
		dst  *[]string
	}{
		{"Wants", &deps.Wants}, {"Requires", &deps.Requires},
		{"RequiredBy", &deps.RequiredBy}, {"Upstream", &deps.Upstream},
		{"Before", &deps.Before}, {"After", &deps.After},
		{"Conflicts", &deps.Conflicts}, {"BoundBy", &deps.BoundBy},
	} {
		*p.dst = sortedFields(props[p.prop])
	}
	return jsonResult(deps), nil, nil
}

// normalizeUnitTyped 是全景视图三工具的单元名门:字符类/遍历检查沿用
// unitNamePattern 纪律,在此之上强制类型后缀属于 unitTypeSuffixes 全集。
// defaultSuffix 非空时补全裸名(timer 视图用 "timer");为空则要求显式后缀
// (依赖视图:补什么后缀都是猜)。
func normalizeUnitTyped(name, defaultSuffix string) (string, error) {
	if name == "" {
		return "", errors.New("name 不能为空")
	}
	if !unitNamePattern.MatchString(name) {
		return "", fmt.Errorf("非法单元名: %q", name)
	}
	if strings.Contains(name, "..") {
		return "", fmt.Errorf("非法单元名(路径遍历): %q", name)
	}
	if !strings.Contains(name, ".") {
		if defaultSuffix == "" {
			return "", fmt.Errorf("单元名须带类型后缀(例如 sshd.service): %q", name)
		}
		name += "." + defaultSuffix
	}
	if !unitTypeSuffixes[name[strings.LastIndexByte(name, '.')+1:]] {
		return "", fmt.Errorf("未知单元类型后缀: %q", name)
	}
	return name, nil
}

// runSystemctl 是 argv 直发的通用底座(与 runSystemctlShow/List 同纪律:
// 30s 兜底超时 + stdin 置空防吞 JSON-RPC 帧);新三工具共用。
func runSystemctl(ctx context.Context, args ...string) (string, error) {
	execCtx, cancel := context.WithTimeout(ctx, systemctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(execCtx, systemctlBinary, args...)
	cmd.Stdin = nil
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("systemctl %s 失败: %w(%s)", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func runSystemctlShowProps(ctx context.Context, unit string, props []string) (map[string]string, error) {
	args := make([]string, 0, 2+2*len(props))
	args = append(args, "show", unit)
	for _, p := range props {
		args = append(args, "--property="+p)
	}
	out, err := runSystemctl(ctx, args...)
	if err != nil {
		return nil, err
	}
	return parseKeyValueLines(out), nil
}

// parseUnitRows 解析 list-units 行:定位首个"带合法类型后缀的单元名"字段,
// 跳过状态字形与对齐空白(纪律同 parseListUnits,后缀判定换用类型全集);
// 后续 LOAD/ACTIVE/SUB 三列不足整行静默跳过。
func parseUnitRows(out string) []failedUnitOut {
	rows := []failedUnitOut{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		idx := slices.IndexFunc(fields, isUnitToken)
		if idx < 0 || idx+3 >= len(fields) {
			continue
		}
		rows = append(rows, failedUnitOut{
			Unit: fields[idx], LoadState: fields[idx+1],
			ActiveState: fields[idx+2], SubState: fields[idx+3],
		})
	}
	return rows
}

func isUnitToken(f string) bool {
	dot := strings.LastIndexByte(f, '.')
	return dot > 0 && unitNamePattern.MatchString(f) && unitTypeSuffixes[f[dot+1:]]
}

// unitNotFoundResult 与 service.query 同姿势:not-found/masked 以逐字文案
// 拒绝(systemctl show 对未知单元也退 0 并回 LoadState,退出码不可依赖)。
func unitNotFoundResult(unit string, props map[string]string) *mcp.CallToolResult {
	if ls := props["LoadState"]; ls == "not-found" || ls == "masked" {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("error: unit %s not found", unit)}},
			IsError: true,
		}
	}
	return nil
}

// usecToRFC3339 把 systemd 微秒时刻转 UTC RFC3339;0/n-a/非法/超一年
// (uint64 饱和即 systemd 的 infinity 哨兵)一律回空串(派生字段可选)。
func usecToRFC3339(raw string) string {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return ""
	}
	t := time.UnixMicro(n).UTC()
	if t.Year() > 2100 {
		return ""
	}
	return t.Format(time.RFC3339)
}

func sortedFields(v string) []string {
	out := strings.Fields(v)
	slices.Sort(out)
	if out == nil {
		out = []string{}
	}
	return out
}
