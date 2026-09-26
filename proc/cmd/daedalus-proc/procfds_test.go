// procfds.go 基元层单测:fd 链接分类、fdinfo pos、cgroup 解析与 \xNN 还原。
package main

import (
	"slices"
	"strings"
	"testing"
)

func TestClassifyFdLink(t *testing.T) {
	for target, want := range map[string]string{
		"socket:[555]":         "socket",
		"pipe:[111]":           "pipe",
		"/var/log/nginx.log":   "file",
		"anon_inode:[eventfd]": "other",
		"[watch]":              "other",
		"/":                    "file",
		"socket:":              "other",
	} {
		if got := classifyFdLink(target); got != want {
			t.Errorf("classifyFdLink(%q) = %s, want %s", target, got, want)
		}
	}
}

func TestReadFdPosAndScan(t *testing.T) {
	root := makeProcFixture(t)
	entries, unreadable, err := scanProcFDs(root, 40, nil)
	if err != nil || unreadable != 0 {
		t.Fatalf("scanProcFDs: %v unreadable=%d", err, unreadable)
	}
	if len(entries) != 5 {
		t.Fatalf("pid40 fd 数 = %d, want 5", len(entries))
	}
	fds := make([]int, 0, len(entries))
	for _, e := range entries {
		fds = append(fds, e.FD)
	}
	slices.Sort(fds)
	if !slices.Equal(fds, []int{3, 4, 5, 6, 7}) {
		t.Errorf("fd 集 = %v", fds)
	}
	byFD := map[int]fdEntry{}
	for _, e := range entries {
		byFD[e.FD] = e
	}
	if byFD[3].Kind != "socket" || byFD[3].Pos == nil || *byFD[3].Pos != 42 {
		t.Errorf("fd3 = %+v", byFD[3])
	}
	if byFD[4].Kind != "file" || byFD[4].Pos == nil || *byFD[4].Pos != 1024 {
		t.Errorf("fd4 = %+v", byFD[4])
	}
	if byFD[5].Kind != "pipe" || byFD[5].Pos != nil {
		t.Errorf("fd5 = %+v", byFD[5])
	}
	if byFD[7].Kind != "other" {
		t.Errorf("fd7 = %+v", byFD[7])
	}
	sockets, _, err := scanProcFDs(root, 40, []string{"socket"})
	if err != nil || len(sockets) != 2 || sockets[0].FD != 3 || sockets[1].FD != 6 {
		t.Errorf("kinds=[socket] = %+v err=%v", sockets, err)
	}
	empty, _, err := scanProcFDs(root, 40, []string{})
	if err != nil || len(empty) != 5 {
		t.Errorf("kinds 空数组应全收: %d err=%v", len(empty), err)
	}
	if _, _, err := scanProcFDs(root, 99, nil); err == nil || !strings.Contains(err.Error(), "失败") {
		t.Errorf("不存在进程应报错,得 %v", err)
	}
}

func TestUnescapeCgroup(t *testing.T) {
	for in, want := range map[string]string{
		`dbus\x2d:1.100`: "dbus-:1.100",
		`a\x20b`:         "a b",
		`plain`:          "plain",
		`\xZZ`:           `\xZZ`,
		`trunc\x2`:       `trunc\x2`,
		`double\x2d\x2d`: "double--",
	} {
		if got := unescapeCgroup(in); got != want {
			t.Errorf("unescapeCgroup(%q) = %q", in, got)
		}
	}
}

func TestParseCgroup(t *testing.T) {
	paths, unit := parseCgroup("0::/system.slice/nginx.service\n")
	if unit != "nginx.service" || paths[""] != "/system.slice/nginx.service" {
		t.Errorf("v2 解析 = %q %+v", unit, paths)
	}
	_, unit = parseCgroup("10:name=systemd:/user.slice/dbus\\x2d:1.100.scope\n")
	if unit != "dbus-:1.100.scope" {
		t.Errorf("v1 转义还原 = %q", unit)
	}
	paths, unit = parseCgroup("0::/\n")
	if unit != "" || paths[""] != "/" {
		t.Errorf("根路径 = %q %+v", unit, paths)
	}
	_, unit = parseCgroup("3:cpu,cpuacct:/kubepods/burstable/podabc\n0::/infra.container\n")
	if unit != "" {
		t.Errorf("无 systemd 行不得产出单元,得 %q", unit)
	}
	if _, unit := parseCgroup("0::/user.slice/user-1000.slice/session-4.scope\n"); unit != "session-4.scope" {
		t.Errorf("本机实录行解析 = %q", unit)
	}
	_, unit = parseCgroup("garbage\n0::\n")
	if unit != "" {
		t.Errorf("坏行应忽略,得 %q", unit)
	}
}
