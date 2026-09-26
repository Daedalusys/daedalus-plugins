// proc 五工具的入参校验、视图载荷与处理器:proc_list / proc_tree /
// proc_fds / proc_listen / proc_cgroup。/proc 基元住在 procfs.go、
// procfds.go、netproc.go;本文件零文件读取逻辑。
//
// 输入面安全:pid 只接受 JSON 整数并强制为正,路径拼接恒用 strconv.Itoa
// (整数没有路径语义);字符串过滤值是等值/包含比较,不进路径与 argv。
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxFilterLen    = 128
	defaultTreeRoot = 1
)

type procListIn struct {
	Filter *string `json:"filter"`
}

type procTreeIn struct {
	RootPID *int `json:"root_pid"`
}

type procFdsIn struct {
	PID   int      `json:"pid"`
	Kinds []string `json:"kinds"`
}

type procListenIn struct {
	Port  *int    `json:"port"`
	Proto *string `json:"proto"`
}

type procCgroupIn struct {
	PID int `json:"pid"`
}

type procListView struct {
	ProcRoot  string     `json:"proc_root"`
	Filter    string     `json:"filter,omitempty"`
	Processes []procInfo `json:"processes"`
	Total     int        `json:"total"`
	Skipped   int        `json:"skipped_unreadable"`
}

type procTreeView struct {
	ProcRoot       string    `json:"proc_root"`
	RootPID        int       `json:"root_pid"`
	Tree           *treeNode `json:"tree"`
	TotalProcesses int       `json:"total_processes"`
}

type procFdsView struct {
	ProcRoot   string    `json:"proc_root"`
	PID        int       `json:"pid"`
	Kinds      []string  `json:"kinds,omitempty"`
	Entries    []fdEntry `json:"entries"`
	Total      int       `json:"total"`
	Unreadable int       `json:"unreadable"`
}

type procListenView struct {
	ProcRoot string `json:"proc_root"`
	Proto    string `json:"proto"`
	Port     int    `json:"port,omitempty"`
	listenResult
}

type procCgroupView struct {
	ProcRoot string            `json:"proc_root"`
	PID      int               `json:"pid"`
	Unit     string            `json:"unit"`
	Cgroups  map[string]string `json:"cgroups"`
}

// validatePID 强制正整数(整数即无路径注入面;0/负数/溢出上限直接拒绝)。
func validatePID(pid int) error {
	if pid <= 0 || pid > 1<<40 {
		return fmt.Errorf("proc: pid 须为正整数: %d", pid)
	}
	return nil
}

// validateFilter 复刻视图 ID 校验:非空、限长、拒绝控制字符与换行。
func validateFilter(s string) error {
	if s == "" || len(s) > maxFilterLen {
		return fmt.Errorf("proc: filter 长度须在 [1, %d]", maxFilterLen)
	}
	if strings.ContainsAny(s, "\x00\n\r") {
		return fmt.Errorf("proc: filter 含控制字符")
	}
	return nil
}

func handleProcList(ctx context.Context, _ *mcp.CallToolRequest, in procListIn) (*mcp.CallToolResult, any, error) {
	const toolName = "proc_list"
	filter := ""
	if in.Filter != nil {
		if err := validateFilter(*in.Filter); err != nil {
			return raisedError(toolName, err), nil, nil
		}
		filter = *in.Filter
	}
	root, err := resolveProcRoot()
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	procs, skipped, err := scanProcList(root, filter)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	return jsonResult(procListView{ProcRoot: root, Filter: filter,
		Processes: procs, Total: len(procs), Skipped: skipped}), nil, nil
}

func handleProcTree(ctx context.Context, _ *mcp.CallToolRequest, in procTreeIn) (*mcp.CallToolResult, any, error) {
	const toolName = "proc_tree"
	rootPID := defaultTreeRoot
	if in.RootPID != nil {
		if err := validatePID(*in.RootPID); err != nil {
			return raisedError(toolName, err), nil, nil
		}
		rootPID = *in.RootPID
	}
	root, err := resolveProcRoot()
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	tree, total, err := buildProcTree(root, rootPID)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	return jsonResult(procTreeView{ProcRoot: root, RootPID: rootPID,
		Tree: tree, TotalProcesses: total}), nil, nil
}

func handleProcFds(ctx context.Context, _ *mcp.CallToolRequest, in procFdsIn) (*mcp.CallToolResult, any, error) {
	const toolName = "proc_fds"
	if err := validatePID(in.PID); err != nil {
		return raisedError(toolName, err), nil, nil
	}
	for _, k := range in.Kinds {
		switch k {
		case "file", "socket", "pipe", "other":
		default:
			return raisedError(toolName, fmt.Errorf("proc: kinds 仅接受 file/socket/pipe/other: %q", k)), nil, nil
		}
	}
	root, err := resolveProcRoot()
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	entries, unreadable, err := scanProcFDs(root, in.PID, in.Kinds)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	return jsonResult(procFdsView{ProcRoot: root, PID: in.PID, Kinds: in.Kinds,
		Entries: entries, Total: len(entries), Unreadable: unreadable}), nil, nil
}

func handleProcListen(ctx context.Context, _ *mcp.CallToolRequest, in procListenIn) (*mcp.CallToolResult, any, error) {
	const toolName = "proc_listen"
	proto := "tcp"
	if in.Proto != nil {
		if *in.Proto != "tcp" && *in.Proto != "udp" {
			return raisedError(toolName, fmt.Errorf("proc: proto 仅接受 tcp/udp: %q", *in.Proto)), nil, nil
		}
		proto = *in.Proto
	}
	port := 0
	if in.Port != nil {
		if *in.Port < 1 || *in.Port > 65535 {
			return raisedError(toolName, fmt.Errorf("proc: port 须在 [1, 65535]: %d", *in.Port)), nil, nil
		}
		port = *in.Port
	}
	root, err := resolveProcRoot()
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	res, err := resolveListen(root, proto, port)
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	return jsonResult(procListenView{ProcRoot: root, Proto: proto,
		Port: port, listenResult: *res}), nil, nil
}

func handleProcCgroup(ctx context.Context, _ *mcp.CallToolRequest, in procCgroupIn) (*mcp.CallToolResult, any, error) {
	const toolName = "proc_cgroup"
	if err := validatePID(in.PID); err != nil {
		return raisedError(toolName, err), nil, nil
	}
	root, err := resolveProcRoot()
	if err != nil {
		return raisedError(toolName, err), nil, nil
	}
	path := filepath.Join(root, strconv.Itoa(in.PID), "cgroup")
	data, err := os.ReadFile(path)
	if err != nil {
		return raisedError(toolName, fmt.Errorf("proc: 读取 %s 失败: %w", path, err)), nil, nil
	}
	paths, unit := parseCgroup(string(data))
	return jsonResult(procCgroupView{ProcRoot: root, PID: in.PID,
		Unit: unit, Cgroups: paths}), nil, nil
}
