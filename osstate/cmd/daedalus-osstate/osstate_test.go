// daedalus-osstate 的行为测试:发行版解析、包管理器优先级与 init 探测全部
// 经 seam 注入,单测永不读取宿主 /etc,也不探测宿主真实 PATH。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/audit"
	"github.com/Daedalusys/daedalus-sdk/sysinfo"
)

// TestMain 把审计链指向临时文件,避免测试期工具调用尝试写默认 /var/log
// 落点产生无关警告噪声。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "daedalus-osstate-audit-main-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建审计临时目录失败: %v\n", err)
		os.Exit(1)
	}
	os.Setenv(audit.EnvLogPath, filepath.Join(dir, "audit.jsonl"))
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// fakePathSet 返回只认给定路径集合的存在性替身(顺序无关,不含隐式路径)。
func fakePathSet(paths ...string) func(string) bool {
	set := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		set[p] = struct{}{}
	}
	return func(p string) bool {
		_, ok := set[p]
		return ok
	}
}

// stubPathExists 在单个测试期内替换包级存在性 seam。
func stubPathExists(t *testing.T, fn func(string) bool) {
	t.Helper()
	old := pathExists
	pathExists = fn
	t.Cleanup(func() { pathExists = old })
}

// stubSysinfoRoot 把发行版采集重定向到夹具根目录。
func stubSysinfoRoot(t *testing.T, root string) {
	t.Helper()
	old := newSysinfoService
	newSysinfoService = func(string) *sysinfo.Service {
		return sysinfo.NewService(nil, root, nil)
	}
	t.Cleanup(func() { newSysinfoService = old })
}

// writeOSRelease 在夹具根下写 etc/os-release。
func writeOSRelease(t *testing.T, root, content string) {
	t.Helper()
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatalf("创建夹具目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(etc, "os-release"), []byte(content), 0o644); err != nil {
		t.Fatalf("写夹具 os-release 失败: %v", err)
	}
}

// roundTrip 把任意回包形态序列化再解析回 map:断言的是线上 JSON 形状,
// 而不是 Go 侧的内部结构体。
func roundTrip(t *testing.T, v any) map[string]any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("序列化回包失败: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("回包不是 JSON 对象: %v (%s)", err, data)
	}
	return out
}

// connectSession 建立内存内客户端/服务器会话。
func connectSession(t *testing.T) (*mcp.ClientSession, context.Context) {
	t.Helper()
	server := newServer()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "osstate-test-client", Version: "0.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("MCP 握手失败: %v", err)
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Errorf("关闭会话失败: %v", err)
		}
		if err := <-serverDone; err != nil {
			t.Errorf("服务器退出异常: %v", err)
		}
	})
	return session, ctx
}

// TestOSStatePayload 验证发行版三字段与包管理器命中结果。
func TestOSStatePayload(t *testing.T) {
	root := t.TempDir()
	writeOSRelease(t, root, "# 注释行\n"+
		"ID=ubuntu\n"+
		"VERSION_ID=\"24.04\"\n"+
		"PRETTY_NAME=\"Ubuntu 24.04 LTS\"\n"+
		"NOISE_WITHOUT_EQUALS\n")
	stubSysinfoRoot(t, root)
	stubPathExists(t, fakePathSet("/usr/bin/dnf"))

	out := roundTrip(t, osStatePayload(newSysinfoService("/").OSRelease()))

	distro, ok := out["distro"].(map[string]any)
	if !ok {
		t.Fatalf("缺少 distro 对象: %v", out)
	}
	if distro["id"] != "ubuntu" || distro["version_id"] != "24.04" || distro["pretty_name"] != "Ubuntu 24.04 LTS" {
		t.Errorf("distro = %v", distro)
	}
	pm, ok := out["package_manager"].(map[string]any)
	if !ok {
		t.Fatalf("缺少 package_manager 对象: %v", out)
	}
	if pm["name"] != "dnf" || pm["binary"] != "/usr/bin/dnf" {
		t.Errorf("package_manager = %v, want {dnf,/usr/bin/dnf}", pm)
	}
	if out["init"] != "unknown" {
		t.Errorf("init = %v, want unknown(夹具无 /run/systemd/system)", out["init"])
	}
}

// TestPackageManagerPriority 钉死候选表顺序:apt 先于 dnf,不按字母序实现。
func TestPackageManagerPriority(t *testing.T) {
	got := detectPackageManager(fakePathSet("/usr/bin/apt-get", "/usr/bin/dnf"))
	if got.Name != "apt" || got.Binary != "/usr/bin/apt-get" {
		t.Errorf("detectPackageManager = %+v, want apt / /usr/bin/apt-get", got)
	}
}

// TestPackageManagerAbsent 全不命中时给 unknown 而不是猜一个。
func TestPackageManagerAbsent(t *testing.T) {
	got := detectPackageManager(fakePathSet())
	if got.Name != "unknown" || got.Binary != "" {
		t.Errorf("detectPackageManager = %+v, want unknown", got)
	}
}

// TestOSStateOSReleaseMissing 夹具为空时整包退化为 error 键,且不带 distro。
func TestOSStateOSReleaseMissing(t *testing.T) {
	stubSysinfoRoot(t, t.TempDir())
	stubPathExists(t, fakePathSet())

	out := roundTrip(t, osStatePayload(newSysinfoService("/").OSRelease()))
	if _, ok := out["error"]; !ok {
		t.Errorf("缺少 error 键: %v", out)
	}
	if _, ok := out["distro"]; ok {
		t.Errorf("读取失败时不应有 distro 键: %v", out)
	}
}

// TestDetectInit 只认 /run/systemd/system 存在,其余一律 unknown。
func TestDetectInit(t *testing.T) {
	if got := detectInit(fakePathSet("/run/systemd/system")); got != "systemd" {
		t.Errorf("detectInit(systemd) = %q, want systemd", got)
	}
	if got := detectInit(fakePathSet()); got != "unknown" {
		t.Errorf("detectInit(空) = %q, want unknown", got)
	}
}
