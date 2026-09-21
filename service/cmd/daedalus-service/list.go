// service.list 工具的实现面(todo 7):过滤模式校验 + systemctl list-units
// 直发 + UNIT/LOAD/ACTIVE/SUB 前四列解析。工具注册仍在 main.go 的
// newServer(plan 文字 pin);本文件与 main.go 同包,分担使两文件都稳居
// 250 纯 LOC 上限之下(包内拆文件的先例: cmd/daedalus-host/paths*.go)。
//
// 安全边界与 service.query 同源:过滤模式先经白名单字符类 + 遍历检查
// (argv 构造前 fail-closed 拒绝),再经 os/exec argv 直发,绝不经过 sh -c。
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/objectmodel"
)

// serviceListIn 对应 service.list(filter: str = "*")。Filter 用 *string
// 区分"客户端未提供"(nil → 应用默认值 "*")与"显式传空串"(→ 拒绝);
// 形态镜像 cmd/daedalus-pkg/main.go 的 dnfListInstalledIn.Pattern。
type serviceListIn struct {
	Filter *string `json:"filter"`
}

// listFilterAll 是过滤模式的通配缺省值:filter 等于它时**不追加**任何
// 过滤参数(systemctl 默认即列全部)。
const listFilterAll = "*"

// handleServiceList 是 service.list 的处理器:过滤模式校验(argv 构造前
// fail-closed)→ systemctl list-units 直发 → 前四列解析 → 按 Name 升序的
// ServiceState 数组。校验/执行失败经 raisedError 呈现为 isError 工具结果。
func handleServiceList(ctx context.Context, _ *mcp.CallToolRequest, in serviceListIn) (*mcp.CallToolResult, any, error) {
	const toolName = "service.list"

	filter := listFilterAll
	if in.Filter != nil {
		filter = *in.Filter
	}
	if err := validateListFilter(filter); err != nil {
		return raisedError(toolName, err), nil, nil
	}
	states, err := runSystemctlList(ctx, filter)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	// todo 20:每次成功的 service.list 调用**一条**条目(计划标题逐字 pin
	// "one state entry per successful ... call",不分单元):Name=生效过滤
	// 模式(缺省即 "*"),载荷=回包同一份 []ServiceState 数组 JSON。
	// best-effort,写失败只落 stderr,不改工具返回值。
	recordServiceState(filter, states)
	return jsonResult(states), nil, nil
}

// validateListFilter 校验列表过滤模式。放行:字面 "*"(语义为不过滤)
// 或匹配单元名白名单字符类且不含 ".." 遍历的模式(unitNamePattern 与
// normalizeUnitName 同源——glob 元字符 '?[]{}$`'"、路径分隔符、空白、
// 非 ASCII、空字节天然被字符类拒掉,非法模式永不抵达 argv,
// 也就没有任何 shell glob 展开或 systemctl 端语义逃逸的通道)。
// filter 是模式而非单元名,故不做 .service 后缀补全。
func validateListFilter(filter string) error {
	if filter == "" {
		return errors.New("filter 不能为空")
	}
	if filter == listFilterAll {
		return nil
	}
	if !unitNamePattern.MatchString(filter) {
		return fmt.Errorf("非法过滤模式: %q", filter)
	}
	if strings.Contains(filter, "..") {
		return fmt.Errorf("非法过滤模式(路径遍历): %q", filter)
	}
	return nil
}

// runSystemctlList argv 直发执行 `systemctl list-units --type=service
// --all --no-pager --no-legend [filter]`(绝不经过 sh -c);filter 为
// "*" 时省略过滤参数。结果按单元名显式升序排序——输出确定性
// 不依赖 systemctl 自身的排序行为。
func runSystemctlList(ctx context.Context, filter string) ([]objectmodel.ServiceState, error) {
	execCtx, cancel := context.WithTimeout(ctx, systemctlTimeout)
	defer cancel()

	args := []string{"list-units", "--type=service", "--all", "--no-pager", "--no-legend"}
	if filter != listFilterAll {
		args = append(args, filter)
	}

	cmd := exec.CommandContext(execCtx, systemctlBinary, args...)
	// stdin 置空(→ /dev/null):服务器 stdin 是 JSON-RPC 帧流,
	// 子进程若继承管道会吞掉未读的协议数据。
	cmd.Stdin = nil
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("systemctl list-units 失败: %w(%s)", err, strings.TrimSpace(stderr.String()))
	}
	states := parseListUnits(stdout.String())
	slices.SortFunc(states, func(a, b objectmodel.ServiceState) int {
		return strings.Compare(a.Name, b.Name)
	})
	return states, nil
}

// parseListUnits 解析 list-units 的行输出:每行以 UNIT/LOAD/ACTIVE/SUB
// 四列打头(DESCRIPTION 列可含空格,只取前四列)。UNIT 列可能带 systemd
// 状态字形前缀(●/*/× 等,与单元名以空白分隔)——不数固定列号,而是
// 定位"首个匹配单元名字符类且以 .service 结尾的字段",字形前缀与
// 无字形的对齐空格都被天然跳过。匹配不到单元名的行(空行、残留表头、
// 杂讯)静默跳过。Properties 键与 service.query 白名单同名(LoadState/
// ActiveState/SubState),DesiredState 恒空(观测态无期望,计划 pin)。
func parseListUnits(out string) []objectmodel.ServiceState {
	states := []objectmodel.ServiceState{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		idx := slices.IndexFunc(fields, func(f string) bool {
			return strings.HasSuffix(f, ".service") && unitNamePattern.MatchString(f)
		})
		if idx < 0 || idx+3 >= len(fields) {
			continue
		}
		states = append(states, objectmodel.ServiceState{
			Kind:         string(objectmodel.KindService),
			Name:         fields[idx],
			DesiredState: "",
			Properties: map[string]string{
				"LoadState":   fields[idx+1],
				"ActiveState": fields[idx+2],
				"SubState":    fields[idx+3],
			},
		})
	}
	return states
}
