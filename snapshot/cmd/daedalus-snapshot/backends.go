package main

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/Daedalusys/daedalus-sdk/sysinfo"
)

// backendProbe 描述一个快照后端的探测方式:固定绝对路径候选表 + 版本旗标。
// 候选表同时是 manifest permissions.run 的唯一事实源(不搜 PATH)。
type backendProbe struct {
	Name        string
	Candidates  []string
	VersionArgs []string
}

// backendProbes 的顺序即推荐优先级:先写的优先。优先级依据是"这个后端能否
// 提供可回滚的真快照",而非字母序 —— btrfs 是子卷快照,rsync 只是文件拷贝兜底。
var backendProbes = []backendProbe{
	{
		Name:        "btrfs",
		Candidates:  []string{"/usr/bin/btrfs", "/usr/sbin/btrfs", "/bin/btrfs", "/sbin/btrfs"},
		VersionArgs: []string{"--version"},
	},
	{
		Name:        "rsync",
		Candidates:  []string{"/usr/bin/rsync", "/bin/rsync"},
		VersionArgs: []string{"--version"},
	},
}

// probeTimeout 是单次版本探测的上限:探测只读自报版本,挂住的进程不该拖住
// 工具调用。
const probeTimeout = 10 * time.Second

// backendStatus 是单个后端的探测结论与证据。
//
// Available 回答的是"后端工具是否就位且能自报版本",不是"当前挂载点能否被
// 快照":后者取决于挂载点的 fstype 与真机条件,由调用方结合 filesystem_info
// 判断。把这两件事分开,是为了不看见 btrfs 二进制就宣布根在 btrfs 上。
type backendStatus struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Evidence  string `json:"evidence"`
}

// backendsIn 是 snapshot_backends 的入参。
type backendsIn struct {
	Mountpoints []string `json:"mountpoints,omitempty"`
}

// probeBackends 逐个探测候选后端,推荐项取第一个可用者;至少一个可用即视为
// 存在回滚路径(本插件只陈述能力,不执行回滚)。
func probeBackends(ctx context.Context, exists func(string) bool, run sysinfo.ExecRunner) ([]backendStatus, string, bool) {
	statuses := make([]backendStatus, 0, len(backendProbes))
	for _, probe := range backendProbes {
		statuses = append(statuses, probeBackend(ctx, probe, exists, run))
	}
	recommended := ""
	for _, st := range statuses {
		if st.Available {
			recommended = st.Name
			break
		}
	}
	return statuses, recommended, recommended != ""
}

// probeBackend 探测单个后端:先按候选顺序 stat,命中后执行版本命令。
// 未命中候选表时绝不 exec —— 没有二进制就没有可写的证据。
func probeBackend(ctx context.Context, probe backendProbe, exists func(string) bool, run sysinfo.ExecRunner) backendStatus {
	binary := ""
	for _, candidate := range probe.Candidates {
		if exists(candidate) {
			binary = candidate
			break
		}
	}
	if binary == "" {
		return backendStatus{
			Name:     probe.Name,
			Evidence: "未找到候选路径: " + strings.Join(probe.Candidates, " "),
		}
	}

	execCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	stdout, stderr, code, err := run(execCtx, binary, probe.VersionArgs)
	command := binary + " " + strings.Join(probe.VersionArgs, " ")

	switch {
	case err != nil:
		return backendStatus{Name: probe.Name, Evidence: command + " => exec 失败: " + err.Error()}
	case code != 0:
		return backendStatus{
			Name:     probe.Name,
			Evidence: fmt.Sprintf("%s => rc=%d: %s", command, code, firstLine(stderr)),
		}
	}

	summary := firstLine(stdout)
	if summary == "" {
		summary = firstLine(stderr)
	}
	if summary == "" {
		summary = "(无输出)"
	}
	return backendStatus{Name: probe.Name, Available: true, Evidence: command + " => " + summary}
}

// snapshotBackendsPayload 组装 snapshot_backends 回包:mountpoints 只做校验与
// 回显,不参与 available 判定。
func snapshotBackendsPayload(ctx context.Context, in backendsIn) map[string]any {
	mountpoints := in.Mountpoints
	if len(mountpoints) == 0 {
		mountpoints = []string{"/"}
	}
	for _, mp := range mountpoints {
		if msg := validateMountpoint(mp); msg != "" {
			return map[string]any{"error": msg}
		}
	}

	backends, recommended, supportsRollback := probeBackends(ctx, pathExists, execCommand)
	return map[string]any{
		"mountpoints":       mountpoints,
		"backends":          backends,
		"recommended":       recommended,
		"supports_rollback": supportsRollback,
	}
}

// firstLine 取输出首行:版本号在第一行,后续行属于噪声。
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// validateMountpoint 在查询前拒绝空串与控制字符。各插件是独立 module,不共享
// 内部包,故本文件保留一份与 osstate 同口径的实现。
func validateMountpoint(mp string) string {
	if mp == "" {
		return "挂载点不能为空"
	}
	if strings.IndexFunc(mp, unicode.IsControl) >= 0 {
		return fmt.Sprintf("非法挂载点: %q", mp)
	}
	return ""
}
