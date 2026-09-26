// 共享 /proc 夹具:一棵与真实内核文件格式逐字段一致的伪 /proc 树。
// 拓扑:1(systemd) → {2 kthreadd 内核线程, 40 nginx → 41 "worker with space"};
// 表文件覆盖 tcp LISTEN/ESTABLISHED、tcp6、udp UNCONN/已连接四类行。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// statLine 拼装 /proc/<pid>/stat:comm 段可含空格/括号;state 之后按真实
// 字段序填充,utime/stime 落在 rest[11]/rest[12](即全局字段 14/15)。
func statLine(pid int, comm, state string, ppid int, utime, stime uint64) string {
	fields := make([]string, 0, 22)
	fields = append(fields, fmt.Sprintf("%d", pid), fmt.Sprintf("(%s)", comm),
		state, fmt.Sprintf("%d", ppid))
	// pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt(字段 5-13)
	fields = append(fields, "0", "0", "0", "0", "-1", "4194304", "133", "0", "0")
	fields = append(fields, fmt.Sprint(utime), fmt.Sprint(stime))
	fields = append(fields, "0", "0", "20", "0", "1", "0")
	return strings.Join(fields, " ") + " 0\n"
}

func writeProcFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// makeProcFixture 生成伪 /proc 根并返回其路径。
func makeProcFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	pidDir := func(pid int) string { return filepath.Join(root, fmt.Sprint(pid)) }

	writeProcFile(t, filepath.Join(pidDir(1), "stat"), statLine(1, "systemd", "S", 0, 500, 100))
	writeProcFile(t, filepath.Join(pidDir(1), "status"), "Name:\tsystemd\nState:\tS (sleeping)\nVmRSS:\t1234 kB\n")
	writeProcFile(t, filepath.Join(pidDir(1), "cmdline"), "/usr/lib/systemd/systemd\x00--switched-root\x00\x00")
	writeProcFile(t, filepath.Join(pidDir(1), "cgroup"), "0::/init.scope\n")

	// 内核线程:cmdline 为空、status 无 VmRSS 行。
	writeProcFile(t, filepath.Join(pidDir(2), "stat"), statLine(2, "kthreadd", "S", 1, 0, 0))
	writeProcFile(t, filepath.Join(pidDir(2), "status"), "Name:\tkthreadd\nState:\tS (sleeping)\n")
	writeProcFile(t, filepath.Join(pidDir(2), "cmdline"), "")
	writeProcFile(t, filepath.Join(pidDir(2), "cgroup"), "0::/\n")

	writeProcFile(t, filepath.Join(pidDir(40), "stat"), statLine(40, "nginx", "R", 1, 77, 5))
	writeProcFile(t, filepath.Join(pidDir(40), "status"), "Name:\tnginx\nVmRSS:\t987 kB\n")
	writeProcFile(t, filepath.Join(pidDir(40), "cmdline"), "/usr/sbin/nginx\x00-g\x00daemon off;\x00")
	writeProcFile(t, filepath.Join(pidDir(40), "cgroup"), "0::/system.slice/nginx.service\n")

	// comm 含空格:验证按最后一个 ')' 切分的解析路径。
	writeProcFile(t, filepath.Join(pidDir(41), "stat"), statLine(41, "worker with space", "S", 40, 10, 2))
	writeProcFile(t, filepath.Join(pidDir(41), "cmdline"), "worker\x00--spawn\x00")
	writeProcFile(t, filepath.Join(pidDir(41), "cgroup"), "10:name=systemd:/user.slice/dbus\\x2d:1.100.scope\n")

	// fd 布局:pid40 持有 8080/53 两个 socket + 一个普通文件 + pipe + anon_inode;
	// pid41 持有 tcp6 的 socket;777 无主(模拟其他用户进程,权限面外)。
	fdBase := func(pid int) string { return filepath.Join(pidDir(pid), "fd") }
	link := func(pid, fd int, target string) {
		t.Helper()
		p := filepath.Join(fdBase(pid), fmt.Sprint(fd))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatalf("symlink %s: %v", p, err)
		}
	}
	link(40, 3, "socket:[555]")
	link(40, 4, "/var/log/nginx.log")
	link(40, 5, "pipe:[111]")
	link(40, 6, "socket:[999]")
	link(40, 7, "anon_inode:[eventfd]")
	link(41, 8, "socket:[888]")
	writeProcFile(t, filepath.Join(pidDir(40), "fdinfo", "3"), "pos:\t42\nflags:\t02000002\n")
	writeProcFile(t, filepath.Join(pidDir(40), "fdinfo", "4"), "pos:\t1024\nmtimes:\t100\n")

	writeProcFile(t, filepath.Join(root, "net", "tcp"),
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1 0000000000000000 100 0 0 10 0\n"+
			"   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777 1 0000000000000000 100 0 0 10 0\n"+
			"   2: 0100007F:1F90 0200007F:C000 01 00000000:00000000 00:00000000 00000000     0        0 556 1 0000000000000000 100 0 0 10 0\n")
	writeProcFile(t, filepath.Join(root, "net", "tcp6"),
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 00000000000000000000000001000000:2382 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 888 1 0000000000000000 100 0 0 10 0\n")
	writeProcFile(t, filepath.Join(root, "net", "udp"),
		"   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 999 1 0000000000000000 100 0 0 10 0\n"+
			"   1: 0100007F:0035 0101007F:4000 07 00000000:00000000 00:00000000 00000000     0        0 1000 1 0000000000000000 100 0 0 10 0\n")
	// net/udp6 刻意缺失:验证表文件缺失容错。
	return root
}
