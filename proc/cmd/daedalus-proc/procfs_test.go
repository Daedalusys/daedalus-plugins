// procfs.go 基元层单测:stat/status/cmdline 解析、pid 枚举、根解析、
// 双采样列表与进程树。真实内核 stat 行样本取自本机 /proc/self/stat。
package main

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// 本机 /proc/self/stat 实录(comm=cat,utime/stime=0):字段序防回归样本。
const realStatLine = "309788 (cat) R 309786 309786 309786 0 -1 4194304 133 0 0 0 5 3 0 0 20 0 1 0 3372605 6098944 448 18446744073709551615\n"

func TestParseStat(t *testing.T) {
	sf, err := parseStat(realStatLine)
	if err != nil {
		t.Fatalf("真实 stat 行解析失败: %v", err)
	}
	if sf.comm != "cat" || sf.state != "R" || sf.ppid != 309786 || sf.utime != 5 || sf.stime != 3 {
		t.Errorf("字段错位: %+v", sf)
	}
	sf, err = parseStat(statLine(41, "worker (with) parens", "S", 40, 10, 2))
	if err != nil || sf.comm != "worker (with) parens" || sf.ppid != 40 || sf.utime != 10 || sf.stime != 2 {
		t.Errorf("comm 含括号解析错误: %+v err=%v", sf, err)
	}
	zeros := func(n int) string { return strings.Repeat("0 ", n) }
	for _, bad := range []string{
		"", "no parens here", "1 (unclosed S 0 0 0 0 0 0 0 0 0 0 0",
		"1 (x) S notanint " + zeros(11) + "0",
		"1 (x) S " + zeros(10) + "notaint " + zeros(2),
		"1 (x) S " + zeros(11) + "notaint " + zeros(1),
	} {
		if _, err := parseStat(bad); err == nil {
			t.Errorf("坏行应报错: %q", bad)
		}
	}
}

func TestParseStatusRSS(t *testing.T) {
	if got := parseStatusRSS("Name:\tx\nVmRSS:\t1234 kB\n"); got != 1234*1024 {
		t.Errorf("VmRSS 解析 = %d", got)
	}
	if got := parseStatusRSS("Name:\tkthreadd\nState:\tS\n"); got != 0 {
		t.Errorf("内核线程无 VmRSS 应为 0,得 %d", got)
	}
	if got := parseStatusRSS("VmRSS:\tabc kB\n"); got != 0 {
		t.Errorf("非整数 VmRSS 应为 0,得 %d", got)
	}
}

func TestReadCmdline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(path, []byte("/usr/sbin/nginx\x00-g\x00daemon off;\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	argv, err := readCmdline(path)
	if err != nil || len(argv) != 3 || argv[2] != "daemon off;" {
		t.Errorf("cmdline 还原错误: %q err=%v", argv, err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if argv, err = readCmdline(path); err != nil || argv != nil {
		t.Errorf("内核线程空 cmdline 应为 nil: %q err=%v", argv, err)
	}
}

func TestResolveProcRoot(t *testing.T) {
	fixture := makeProcFixture(t)
	t.Setenv(EnvProcRoot, fixture)
	if root, err := resolveProcRoot(); err != nil || root != fixture {
		t.Errorf("env 覆盖失败: %q %v", root, err)
	}
	t.Setenv(EnvProcRoot, filepath.Join(t.TempDir(), "missing"))
	if _, err := resolveProcRoot(); err == nil || !strings.Contains(err.Error(), "不可读") {
		t.Errorf("env 指向缺失路径应显式报错,得 %v", err)
	}
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvProcRoot, plain)
	if _, err := resolveProcRoot(); err == nil {
		t.Error("env 指向普通文件应报错(非目录)")
	}
	t.Setenv(EnvProcRoot, "")
	if runtime.GOOS != "linux" {
		t.Skip("默认 /proc 候选仅 linux 有意义")
	}
	if root, err := resolveProcRoot(); err != nil || root != defaultProcRoot {
		t.Errorf("默认候选 = %q err=%v", root, err)
	}
}

func TestListPIDs(t *testing.T) {
	root := makeProcFixture(t)
	pids, err := listPIDs(root)
	if err != nil || !slices.Equal(pids, []int{1, 2, 40, 41}) {
		t.Errorf("listPIDs = %v err=%v", pids, err)
	}
	if _, err := listPIDs(filepath.Join(root, "missing")); err == nil {
		t.Error("不可读根应报错")
	}
}

func TestScanProcList(t *testing.T) {
	procs, skipped, err := scanProcList(makeProcFixture(t), "")
	if err != nil || skipped != 0 {
		t.Fatalf("scanProcList: %v skipped=%d", err, skipped)
	}
	if len(procs) != 4 {
		t.Fatalf("进程数 = %d, want 4", len(procs))
	}
	nginx := procs[2]
	if nginx.PID != 40 || nginx.State != "R" || nginx.PPID != 1 ||
		nginx.CPUJiffies != 82 || nginx.MemoryRSSBytes != 987*1024 ||
		len(nginx.Cmdline) != 3 || nginx.CPUPercent != 0 {
		t.Errorf("nginx 行错误: %+v", nginx)
	}
	if procs[1].PID != 2 || procs[1].Cmdline != nil || procs[1].MemoryRSSBytes != 0 {
		t.Errorf("内核线程行错误: %+v", procs[1])
	}
	if procs[3].Name != "worker with space" {
		t.Errorf("comm 含空格行错误: %+v", procs[3])
	}
	if procs, _, _ := scanProcList(makeProcFixture(t), "daemon off;"); len(procs) != 1 || procs[0].PID != 40 {
		t.Errorf("filter 命中命令行失败: %+v", procs)
	}
	if procs, _, _ := scanProcList(makeProcFixture(t), "zzz"); len(procs) != 0 {
		t.Errorf("无命中 filter 应得空列表: %+v", procs)
	}
}

func TestBuildProcTree(t *testing.T) {
	root := makeProcFixture(t)
	tree, total, err := buildProcTree(root, 1)
	if err != nil || total != 4 {
		t.Fatalf("buildProcTree: %v total=%d", err, total)
	}
	if tree.PID != 1 || len(tree.Children) != 2 ||
		tree.Children[0].PID != 2 || tree.Children[1].PID != 40 ||
		len(tree.Children[1].Children) != 1 || tree.Children[1].Children[0].PID != 41 {
		t.Errorf("树形态错误: %+v", tree)
	}
	if tree.Children[1].Children[0].Name != "worker with space" {
		t.Errorf("树节点 name 缺失: %+v", tree.Children[1].Children[0])
	}
	if _, _, err := buildProcTree(root, 999); err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Errorf("根进程缺失应报错,得 %v", err)
	}
}
