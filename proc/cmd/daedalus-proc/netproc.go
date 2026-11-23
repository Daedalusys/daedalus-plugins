// /proc/net 监听表解析与 socket inode → pid 反查:tcp/tcp6 取 LISTEN(0A)
// 状态,udp/udp6 取远端全零(未连接绑定)条目;进程归属经全量扫描
// /proc/<pid>/fd 的 socket:[ino] 链接建立映射。fd 不可读(非 root 运行时读
// 他人进程)时降级为可见进程 cmdline 的端口 token 线索,不把「读不到」当成
// 「无主」。零 exec(不用 ss/netstat)、零写入。
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// socketEntry 是 /proc/net/{tcp,tcp6,udp,udp6} 中一行解析结果。
type socketEntry struct {
	Proto   string `json:"proto"`
	LocalIP string `json:"local_address"`
	Port    int    `json:"local_port"`
	State   string `json:"state"`
	Inode   uint64 `json:"inode"`
}

// listenResult 是 proc_listen 视图载荷;unowned 为反查不到进程的条目数。
type listenResult struct {
	Entries []listenEntry `json:"listeners"`
	Scanned int           `json:"scanned_sockets"`
	Unowned int           `json:"unowned_sockets"`
}

// listenEntry 是单个监听条目;attribution 三态见 attribution* 常量。
type listenEntry struct {
	socketEntry
	PIDs        []int             `json:"pids"`
	Names       []string          `json:"names"`
	Attribution string            `json:"attribution"`
	Hints       []attributionHint `json:"hints,omitempty"`
}

// 端口归属三态:fd_match 由 /proc/<pid>/fd 反查确定;cmdline_hint 是 fd 不可读
// 时可见进程 cmdline 的端口 token 命中;unresolved 表示两条证据都拿不到。
const (
	attributionFDMatch     = "fd_match"
	attributionCmdlineHint = "cmdline_hint"
	attributionUnresolved  = "unresolved"
)

// attributionHint 是端口归属的线索级证据:归因不来自 /proc/<pid>/fd(权限不足),
// 而是来自可见进程的 cmdline 端口 token 命中 + cgroup 单元定位。
type attributionHint struct {
	PID        int    `json:"pid"`
	Cmdline    string `json:"cmdline"`
	CgroupUnit string `json:"cgroup_unit,omitempty"`
	Match      string `json:"match"`
}

// portTokenMatch 按独立 token 判定 cmdline 是否指向该端口:argv 恰好等于端口号,
// 或以 "--port=<port>" / ":<port>" 形式出现。不做裸子串匹配 —— 否则 1180801
// 会把无关进程指认为 18080 的属主。
func portTokenMatch(args []string, port int) bool {
	want := strconv.Itoa(port)
	suffix := ":" + want
	for _, a := range args {
		if a == want || a == "--port="+want || strings.HasSuffix(a, suffix) {
			return true
		}
	}
	return false
}

// hintCandidate 是一个可见进程的 cmdline 快照;cgroup 单元留到命中时再解析。
type hintCandidate struct {
	pid  int
	argv []string
}

// cmdlineCandidates 枚举 /proc 下可读进程的 cmdline,作为 fd 反查失败时的
// 线索来源。读不到 cmdline 的进程(hidepid 下的他人进程、内核线程)跳过。
func cmdlineCandidates(root string) []hintCandidate {
	pids, err := listPIDs(root)
	if err != nil {
		return nil
	}
	var out []hintCandidate
	for _, pid := range pids {
		argv, err := readCmdline(filepath.Join(root, strconv.Itoa(pid), "cmdline"))
		if err != nil || len(argv) == 0 {
			continue
		}
		out = append(out, hintCandidate{pid: pid, argv: argv})
	}
	return out
}

// cmdlineHints 在候选进程里找端口 token 命中者;命中时顺带解析该进程的
// cgroup 单元,让线索能落到 systemd 单元上。
func cmdlineHints(root string, cands []hintCandidate, port int) []attributionHint {
	var out []attributionHint
	for _, c := range cands {
		if !portTokenMatch(c.argv, port) {
			continue
		}
		h := attributionHint{PID: c.pid, Cmdline: strings.Join(c.argv, " "), Match: "cmdline"}
		if data, err := os.ReadFile(filepath.Join(root, strconv.Itoa(c.pid), "cgroup")); err == nil {
			_, h.CgroupUnit = parseCgroup(string(data))
		}
		out = append(out, h)
	}
	return out
}

// netFileStates 是各表文件对应的协议标签。
var netFiles = []struct {
	name, proto string
}{
	{"net/tcp", "tcp"}, {"net/tcp6", "tcp"},
	{"net/udp", "udp"}, {"net/udp6", "udp"},
}

// parseNetLine 解析数据行(首列形如 "12:",字段序:local rem st ... inode[9])。
func parseNetLine(line, proto string) (socketEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 10 || !strings.HasSuffix(fields[0], ":") {
		return socketEntry{}, false
	}
	st, err := strconv.ParseUint(fields[3], 16, 8)
	if err != nil {
		return socketEntry{}, false
	}
	e := socketEntry{Proto: proto}
	if e.LocalIP, e.Port, err = parseHexAddress(fields[1]); err != nil {
		return socketEntry{}, false
	}
	rem, remPort, err := parseHexAddress(fields[2])
	if err != nil {
		return socketEntry{}, false
	}
	switch proto {
	case "tcp":
		if st != 0x0A {
			return socketEntry{}, false
		}
		e.State = "LISTEN"
	case "udp":
		// udp 无 LISTEN 态:远端地址+端口全零 = 未连接绑定(服务监听形态)。
		if (rem != "0.0.0.0" && rem != "::") || remPort != 0 {
			return socketEntry{}, false
		}
		e.State = "UNCONN"
	}
	if inode, err := strconv.ParseUint(fields[9], 10, 64); err == nil {
		e.Inode = inode
	}
	return e, true
}

// parseHexAddress 解析 "0100007F:1F90" 形态:IP 按 32 位字小端序
// (x86/arm64 内核打印规则),端口为大写十六进制。
func parseHexAddress(s string) (string, int, error) {
	ipPart, portPart, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, fmt.Errorf("缺 ':' 分隔: %q", s)
	}
	port, err := strconv.ParseUint(portPart, 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("端口十六进制非法: %q", portPart)
	}
	raw, err := hex.DecodeString(ipPart)
	if err != nil {
		return "", 0, fmt.Errorf("IP 十六进制非法: %q", ipPart)
	}
	if n := len(raw); n != 4 && n != 16 {
		return "", 0, fmt.Errorf("IP 字节数异常: %d", n)
	}
	// 每 4 字节一组反转(小端);v4 反转后即点分十进制。
	buf := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		for j := 0; j < 4; j++ {
			buf[i+j] = raw[i+3-j]
		}
	}
	return net.IP(buf).String(), int(port), nil
}

// scanListenSockets 读取四类表并按 proto/port 过滤;表文件缺失跳过
// (如精简容器无 IPv6),四类全无才报错。
func scanListenSockets(root, proto string, port int) ([]socketEntry, error) {
	var out []socketEntry
	seen := 0
	for _, nf := range netFiles {
		if !strings.HasPrefix(nf.proto, proto) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, nf.name))
		if err != nil {
			continue
		}
		seen++
		for _, line := range strings.Split(string(data), "\n") {
			e, ok := parseNetLine(line, proto)
			if !ok || (port > 0 && e.Port != port) {
				continue
			}
			out = append(out, e)
		}
	}
	if seen == 0 {
		return nil, fmt.Errorf("proc: %s 下 net/%ss、net/%ss6 表均不可读", root, proto, proto)
	}
	return out, nil
}

// socketOwnerMap 全量扫描 /proc/<pid>/fd,建 inode → pids 映射;
// 无权限的进程目录静默跳过(反查降级为 unowned)。
func socketOwnerMap(root string) map[uint64][]int {
	m := map[uint64][]int{}
	pids, err := listPIDs(root)
	if err != nil {
		return m
	}
	for _, pid := range pids {
		dir := filepath.Join(root, strconv.Itoa(pid), "fd")
		links, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, l := range links {
			target, err := os.Readlink(filepath.Join(dir, l.Name()))
			if err != nil {
				continue
			}
			ino, ok := socketInode(target)
			if !ok {
				continue
			}
			if !slicesContains(m[ino], pid) {
				m[ino] = append(m[ino], pid)
			}
		}
	}
	return m
}

func socketInode(target string) (uint64, bool) {
	rest, ok := strings.CutPrefix(target, "socket:[")
	if !ok {
		return 0, false
	}
	rest, ok = strings.CutSuffix(rest, "]")
	if !ok {
		return 0, false
	}
	ino, err := strconv.ParseUint(rest, 10, 64)
	return ino, err == nil && ino > 0
}

func slicesContains(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// resolveListen 组合表扫描与 inode 反查,产出带进程归属的监听视图;
// fd 反查不到时按可见进程 cmdline 的端口 token 给出线索级归因。
func resolveListen(root, proto string, port int) (*listenResult, error) {
	socks, err := scanListenSockets(root, proto, port)
	if err != nil {
		return nil, err
	}
	owners := socketOwnerMap(root)
	names := map[int]string{}
	res := &listenResult{Entries: []listenEntry{}, Scanned: len(socks)}
	var cands []hintCandidate
	candsReady := false
	for _, e := range socks {
		pids := owners[e.Inode]
		entry := listenEntry{socketEntry: e, PIDs: pids}
		if len(pids) == 0 {
			res.Unowned++
			entry.PIDs = []int{}
			entry.Attribution = attributionUnresolved
			if e.Port > 0 {
				if !candsReady {
					cands = cmdlineCandidates(root)
					candsReady = true
				}
				entry.Hints = cmdlineHints(root, cands, e.Port)
				if len(entry.Hints) > 0 {
					entry.Attribution = attributionCmdlineHint
				}
			}
		} else {
			entry.Attribution = attributionFDMatch
			entry.Names = make([]string, 0, len(pids))
			for _, pid := range pids {
				if _, ok := names[pid]; !ok {
					if st, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat")); err == nil {
						if sf, err := parseStat(string(st)); err == nil {
							names[pid] = sf.comm
						}
					}
				}
				entry.Names = append(entry.Names, names[pid])
			}
		}
		res.Entries = append(res.Entries, entry)
	}
	return res, nil
}
