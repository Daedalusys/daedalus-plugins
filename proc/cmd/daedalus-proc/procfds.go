// proc_fds 与 proc_cgroup 的 /proc 读取基元:fd 符号链接分类(含 fdinfo
// pos)与 cgroup 路径解析、systemd 单元定位。零 exec、零写入。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// fdEntry 是单个文件描述符视图:kind ∈ file|socket|pipe|other;
// target 为符号链接目标(socket:[ino]/pipe:[ino]/路径);pos 为 fdinfo 的
// 读写偏移(不可读时省略)。
type fdEntry struct {
	FD     int    `json:"fd"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Pos    *int64 `json:"pos,omitempty"`
}

// classifyFdLink 按链接目标前缀分类,判据与 lsof 惯例一致。
func classifyFdLink(target string) string {
	switch {
	case strings.HasPrefix(target, "socket:["):
		return "socket"
	case strings.HasPrefix(target, "pipe:["):
		return "pipe"
	case strings.HasPrefix(target, "/"):
		return "file"
	default:
		return "other"
	}
}

// readFdPos 从 fdinfo 抽 pos 字段;缺文件/缺行/非整数一律返回 nil(不报错,
// 特殊 fd 本无偏移)。
func readFdPos(path string) *int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "pos:"); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return &n
			}
			return nil
		}
	}
	return nil
}

// scanProcFDs 读取 /proc/<pid>/fd 全量条目并按 kinds 白名单过滤
// (kinds 为空 = 全收,含 other 类如 anon_inode/eventfd);单个 fd 在
// 枚举与 readlink 之间被关闭的竞态计入 unreadable 跳过。
func scanProcFDs(root string, pid int, kinds []string) ([]fdEntry, int, error) {
	dir := filepath.Join(root, strconv.Itoa(pid), "fd")
	links, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, fmt.Errorf("proc: 读取 %s 失败: %w", dir, err)
	}
	wanted := map[string]bool{}
	for _, k := range kinds {
		wanted[k] = true
	}
	entries := make([]fdEntry, 0, len(links))
	unreadable := 0
	for _, l := range links {
		fd, err := strconv.Atoi(l.Name())
		if err != nil {
			unreadable++
			continue
		}
		target, err := os.Readlink(filepath.Join(dir, l.Name()))
		if err != nil {
			unreadable++
			continue
		}
		kind := classifyFdLink(target)
		if len(wanted) > 0 && !wanted[kind] {
			continue
		}
		entries = append(entries, fdEntry{
			FD: fd, Kind: kind, Target: target,
			Pos: readFdPos(filepath.Join(root, strconv.Itoa(pid), "fdinfo", l.Name())),
		})
	}
	return entries, unreadable, nil
}

// unitSuffixes 是 systemd 单元类型后缀;路径段以其一结尾即视为单元名。
var unitSuffixes = []string{".service", ".socket", ".target", ".timer",
	".mount", ".slice", ".scope", ".swap", ".path"}

// unescapeCgroup 复刻 cgroup v2 对控制字符的 \xNN 转义还原(空格=\x20)。
func unescapeCgroup(seg string) string {
	for {
		i := strings.Index(seg, `\x`)
		if i < 0 || i+4 > len(seg) {
			return seg
		}
		b, err := strconv.ParseUint(seg[i+2:i+4], 16, 8)
		if err != nil {
			return seg
		}
		seg = seg[:i] + string(rune(b)) + seg[i+4:]
	}
}

// parseCgroup 解析 /proc/<pid>/cgroup:逐行 "hierarchy:controllers:path",
// 返回 控制器→路径 map 与最内层 systemd 单元名(取 v2 "0::" 行或 v1
// name=systemd 行的最后一个路径段,须以单元后缀结尾;否则 unit 为空)。
func parseCgroup(data string) (paths map[string]string, unit string) {
	paths = map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[2] == "" {
			continue
		}
		paths[parts[1]] = parts[2]
		systemdLine := parts[0] == "0" && parts[1] == "" || strings.Contains(parts[1], "systemd")
		if !systemdLine {
			continue
		}
		seg := parts[2]
		if k := strings.LastIndex(seg, "/"); k >= 0 {
			seg = seg[k+1:]
		}
		seg = unescapeCgroup(seg)
		for _, suf := range unitSuffixes {
			if strings.HasSuffix(seg, suf) {
				unit = seg
			}
		}
	}
	return paths, unit
}
