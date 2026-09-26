// netproc.go 基元层单测:十六进制地址/端口解码、表行判别、inode→pid 反查
// 与监听视图组合。夹具表行与本机 /proc/net/tcp 实录同构。
package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseHexAddress(t *testing.T) {
	for _, tc := range []struct {
		s, ip string
		port  int
	}{
		{"0100007F:1F90", "127.0.0.1", 8080},
		{"00000000:0016", "0.0.0.0", 22},
		{"00000000000000000000000001000000:2382", "::1", 9090},
		{"00000000000000000000000000000000:0000", "::", 0},
	} {
		ip, port, err := parseHexAddress(tc.s)
		if err != nil || ip != tc.ip || port != tc.port {
			t.Errorf("parseHexAddress(%q) = %q,%d,%v want %q,%d", tc.s, ip, port, err, tc.ip, tc.port)
		}
	}
	for _, bad := range []string{"0100007F", "0100007F:zzzz", "XYZ:0050", "0100:1F90"} {
		if _, _, err := parseHexAddress(bad); err == nil {
			t.Errorf("坏地址应报错: %q", bad)
		}
	}
}

func TestParseNetLine(t *testing.T) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
	if _, ok := parseNetLine(header, "tcp"); ok {
		t.Error("表头行不应命中")
	}
	e, ok := parseNetLine("   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1 0 100 0 0 10 0", "tcp")
	if !ok || e.State != "LISTEN" || e.Port != 8080 || e.Inode != 555 || e.LocalIP != "127.0.0.1" {
		t.Errorf("LISTEN 行 = %+v ok=%v", e, ok)
	}
	if _, ok := parseNetLine("   2: 0100007F:1F90 0200007F:C000 01 00000000:00000000 00:00000000 00000000     0        0 556 1 0 100 0 0 10 0", "tcp"); ok {
		t.Error("ESTABLISHED 行必须排除")
	}
	if _, ok := parseNetLine("   1: 0100007F:0035 0101007F:4000 07 00000000:00000000 00:00000000 00000000     0        0 1000 1 0 100 0 0 10 0", "udp"); ok {
		t.Error("已连接 udp 行必须排除")
	}
	if _, ok := parseNetLine("   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 999 1 0 100 0 0 10 0", "udp"); !ok {
		t.Error("未连接绑定 udp 行必须收录")
	}
	for _, bad := range []string{"", "x: y", "0: nocolon 00000000:0000 0A a b c d e 1 f", "0: 0100007F:1F90 00000000:0000 zz a b c d e 1 f"} {
		if _, ok := parseNetLine(bad, "tcp"); ok {
			t.Errorf("坏行应跳过: %q", bad)
		}
	}
}

func TestSocketInode(t *testing.T) {
	if ino, ok := socketInode("socket:[555]"); !ok || ino != 555 {
		t.Errorf("socketInode = %d,%v", ino, ok)
	}
	for _, target := range []string{"pipe:[555]", "socket:[", "socket:[x]", "socket:[0]", "/dev/null"} {
		if _, ok := socketInode(target); ok {
			t.Errorf("非 socket inode 链接误判: %q", target)
		}
	}
}

func TestResolveListen(t *testing.T) {
	root := makeProcFixture(t)
	res, err := resolveListen(root, "tcp", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != 3 || res.Unowned != 1 || len(res.Entries) != 3 {
		t.Fatalf("tcp 视图 = %+v", res)
	}
	first := res.Entries[0]
	if first.Port != 8080 || !slices.Equal(first.PIDs, []int{40}) || len(first.Names) != 1 || first.Names[0] != "nginx" {
		t.Errorf("8080 归属错误: %+v", first)
	}
	ssh := res.Entries[1]
	if ssh.Port != 22 || ssh.LocalIP != "0.0.0.0" || len(ssh.PIDs) != 0 {
		t.Errorf("22 应 unowned: %+v", ssh)
	}
	v6 := res.Entries[2]
	if v6.Port != 9090 || v6.LocalIP != "::1" || !slices.Equal(v6.PIDs, []int{41}) {
		t.Errorf("tcp6 行错误: %+v", v6)
	}
	if res, err = resolveListen(root, "tcp", 8080); err != nil || len(res.Entries) != 1 || res.Scanned != 1 {
		t.Errorf("port 过滤 = %+v err=%v", res, err)
	}
	if res, err = resolveListen(root, "tcp", 4444); err != nil || len(res.Entries) != 0 || res.Scanned != 0 {
		t.Errorf("无命中端口应为空: %+v err=%v", res, err)
	}
	udp, err := resolveListen(root, "udp", 0)
	if err != nil || udp.Scanned != 1 || udp.Entries[0].Port != 53 || !slices.Equal(udp.Entries[0].PIDs, []int{40}) {
		t.Errorf("udp 视图 = %+v err=%v", udp, err)
	}
	if _, err := resolveListen(filepath.Join(root, "missing"), "udp", 0); err == nil ||
		!strings.Contains(err.Error(), "均不可读") {
		t.Errorf("四类表缺失应报错,得 %v", err)
	}
}
