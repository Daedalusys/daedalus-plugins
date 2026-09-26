// /proc 只读基元:根目录解析、pid 枚举、stat/status/cmdline 解析、
// 双采样 CPU 快照与进程树构建。全部经 os.ReadDir/ReadFile/Readlink,
// 零 exec、零写入;pid 参数一律先验证为正整数再用 strconv.Itoa 拼接,
// 攻击面不进入路径(动态路径 = 代码生成的整型目录名)。
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// EnvProcRoot 覆盖 /proc 根目录(测试夹具与容器内挂载点用);指向不存在
// 或不可读路径时显式报错,绝不静默回落。
const EnvProcRoot = "DAEDALUS_PROC_ROOT"

const (
	defaultProcRoot = "/proc"
	// userHZ 即 USER_HZ:Linux 主流架构(x86_64/aarch64)恒为 100,
	// stat 的 utime/stime 以该粒度的 jiffies 计。
	userHZ = 100
	// cpuSampleInterval 是 proc_list 双采样间隔;CPU% = Δjiffies/USER_HZ/Δt。
	cpuSampleInterval = 100 * time.Millisecond
)

// ErrNoUsableProcRoot 表示默认与 env 候选均不可读——显式报错。
var ErrNoUsableProcRoot = errors.New("proc: /proc 根目录不可读")

// resolveProcRoot 解析链:env 覆盖(必须存在且可读)→ /proc → 显式错误。
func resolveProcRoot() (string, error) {
	if v := os.Getenv(EnvProcRoot); v != "" {
		if !usableProcRoot(v) {
			return "", fmt.Errorf("%w: %s=%q 不存在或不可读", ErrNoUsableProcRoot, EnvProcRoot, v)
		}
		return v, nil
	}
	if !usableProcRoot(defaultProcRoot) {
		return "", fmt.Errorf("%w: %s", ErrNoUsableProcRoot, defaultProcRoot)
	}
	return defaultProcRoot, nil
}

// usableProcRoot 要求"可打开且可列目录":普通文件 Open 也成功,
// 必须用 Readdirnames 判定目录语义;空目录(EOF)算可用。
func usableProcRoot(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	return err == nil || errors.Is(err, io.EOF)
}

// listPIDs 枚举根目录下的数字子目录名并升序返回。不可整体 ReadDir 即报错;
// 单个 pid 在枚举与读取之间消失(进程退出竞态)由调用方按跳过处理。
func listPIDs(root string) ([]int, error) {
	dirs, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("proc: 读取 %s 失败: %w", root, err)
	}
	var pids []int
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		if n, err := strconv.Atoi(d.Name()); err == nil && n > 0 {
			pids = append(pids, n)
		}
	}
	sort.Ints(pids)
	return pids, nil
}

// statFields 是 /proc/<pid>/stat 中本视图消费的字段子集。comm 可含空格与
// 括号,故按最后一个 ')' 切分,后续字段自 state 起按空白序号取。
type statFields struct {
	comm  string
	state string
	ppid  int
	utime uint64
	stime uint64
}

func parseStat(data string) (statFields, error) {
	open := strings.IndexByte(data, '(')
	closing := strings.LastIndexByte(data, ')')
	if open < 0 || closing <= open {
		return statFields{}, errors.New("proc: stat 缺少 comm 括号段")
	}
	f := statFields{comm: data[open+1 : closing]}
	rest := strings.Fields(data[closing+1:])
	// rest[0]=state(字段3) rest[1]=ppid(字段4) rest[11]=utime(14) rest[12]=stime(15)
	if len(rest) < 13 {
		return statFields{}, fmt.Errorf("proc: stat 字段不足: %d", len(rest))
	}
	f.state = rest[0]
	ppid, err := strconv.Atoi(rest[1])
	if err != nil {
		return statFields{}, fmt.Errorf("proc: stat ppid 非整数: %q", rest[1])
	}
	f.ppid = ppid
	if f.utime, err = strconv.ParseUint(rest[11], 10, 64); err != nil {
		return statFields{}, fmt.Errorf("proc: stat utime 非整数: %q", rest[11])
	}
	if f.stime, err = strconv.ParseUint(rest[12], 10, 64); err != nil {
		return statFields{}, fmt.Errorf("proc: stat stime 非整数: %q", rest[12])
	}
	return f, nil
}

// parseStatusRSS 抽取 /proc/<pid>/status 的 VmRSS( kB → 字节);
// 内核线程无该行走零值分支,不是错误。
func parseStatusRSS(data string) int64 {
	for _, line := range strings.Split(data, "\n") {
		if v, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			fields := strings.Fields(v)
			if len(fields) >= 1 {
				if kb, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
					return kb * 1024
				}
			}
			return 0
		}
	}
	return 0
}

// readCmdline 读 NUL 分隔命令行并还原参数数组;内核线程该文件为空,返回 nil。
func readCmdline(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var argv []string
	for _, piece := range strings.Split(string(data), "\x00") {
		if piece != "" {
			argv = append(argv, piece)
		}
	}
	return argv, nil
}

// procInfo 是精简进程行:pid/name/ppid/state/cmdline/cpu/mem(jiffies 累计值
// 一并给出,CPU% 为双采样窗口内的均值)。
type procInfo struct {
	PID            int      `json:"pid"`
	Name           string   `json:"name"`
	PPID           int      `json:"ppid"`
	State          string   `json:"state"`
	Cmdline        []string `json:"cmdline"`
	CPUPercent     float64  `json:"cpu_percent"`
	MemoryRSSBytes int64    `json:"memory_rss_bytes"`
	CPUJiffies     uint64   `json:"cpu_time_jiffies"`
}

// procSnapshot 单次读取一个 pid 的 stat/status/cmdline;读取失败(含竞态
// 消失、权限不足)返回 err,由调用方计入跳过数。
func procSnapshot(root string, pid int) (procInfo, statFields, error) {
	base := filepath.Join(root, strconv.Itoa(pid))
	st, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return procInfo{}, statFields{}, err
	}
	sf, err := parseStat(string(st))
	if err != nil {
		return procInfo{}, statFields{}, err
	}
	info := procInfo{PID: pid, Name: sf.comm, PPID: sf.ppid, State: sf.state,
		CPUJiffies: sf.utime + sf.stime}
	if rss, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
		info.MemoryRSSBytes = parseStatusRSS(string(rss))
	}
	if argv, err := readCmdline(filepath.Join(base, "cmdline")); err == nil {
		info.Cmdline = argv
	}
	return info, sf, nil
}

// scanProcList 双采样生成进程快照列表:第一遍全量读 stat,固定间隔后第二遍
// 只重读 stat 求 Δjiffies;单进程读取失败静默跳过并计数(竞态是常态)。
func scanProcList(root, filter string) ([]procInfo, int, error) {
	pids, err := listPIDs(root)
	if err != nil {
		return nil, 0, err
	}
	type firstPass struct {
		info procInfo
		sf   statFields
	}
	pass1 := make([]firstPass, 0, len(pids))
	skipped := 0
	for _, pid := range pids {
		info, sf, err := procSnapshot(root, pid)
		if err != nil {
			skipped++
			continue
		}
		pass1 = append(pass1, firstPass{info: info, sf: sf})
	}
	time.Sleep(cpuSampleInterval)
	out := make([]procInfo, 0, len(pass1))
	for _, fp := range pass1 {
		st, err := os.ReadFile(filepath.Join(root, strconv.Itoa(fp.info.PID), "stat"))
		if err == nil {
			if sf2, err2 := parseStat(string(st)); err2 == nil {
				delta := int64(sf2.utime+sf2.stime) - int64(fp.sf.utime+fp.sf.stime)
				if delta > 0 {
					fp.info.CPUPercent = float64(delta) / float64(userHZ) /
						cpuSampleInterval.Seconds() * 100
				}
			}
		}
		if filter == "" || procMatches(fp.info, filter) {
			out = append(out, fp.info)
		}
	}
	return out, skipped, nil
}

func procMatches(info procInfo, filter string) bool {
	if strings.Contains(info.Name, filter) {
		return true
	}
	return strings.Contains(strings.Join(info.Cmdline, " "), filter)
}

// treeNode 是 proc_tree 的嵌套节点;Children 按 pid 升序。
type treeNode struct {
	PID      int        `json:"pid"`
	Name     string     `json:"name"`
	Children []treeNode `json:"children"`
}

// buildProcTree 以 rootPID 为根构建进程树。visited 集合防 ppid 环导致的
// 无限下降(异常 ppid 子树被剪枝,不报错)。
func buildProcTree(root string, rootPID int) (*treeNode, int, error) {
	pids, err := listPIDs(root)
	if err != nil {
		return nil, 0, err
	}
	children := map[int][]int{}
	names := map[int]string{}
	for _, pid := range pids {
		base := filepath.Join(root, strconv.Itoa(pid))
		st, err := os.ReadFile(filepath.Join(base, "stat"))
		if err != nil {
			continue
		}
		sf, err := parseStat(string(st))
		if err != nil {
			continue
		}
		children[sf.ppid] = append(children[sf.ppid], pid)
		names[pid] = sf.comm
	}
	for k := range children {
		sort.Ints(children[k])
	}
	if _, ok := names[rootPID]; !ok {
		return nil, 0, fmt.Errorf("proc: 根进程 %d 不存在", rootPID)
	}
	visited := map[int]bool{}
	var walk func(int) treeNode
	walk = func(pid int) treeNode {
		visited[pid] = true
		node := treeNode{PID: pid, Name: names[pid], Children: []treeNode{}}
		for _, c := range children[pid] {
			if visited[c] {
				continue
			}
			node.Children = append(node.Children, walk(c))
		}
		return node
	}
	tree := walk(rootPID)
	return &tree, len(names), nil
}
