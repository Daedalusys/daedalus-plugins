// manifest 一致性测试:清单声明的工具与权限必须与二进制实际行为逐项相等,
// 且源码里不得出现任何写/建/删符号(只读铁律的本地闸)。
package main

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/plugin"
)

const manifestRelPath = "../../daedalus.plugin.json"

// loadManifest 读取并解析本插件 manifest。
func loadManifest(t *testing.T) *plugin.Manifest {
	t.Helper()
	data, err := os.ReadFile(manifestRelPath)
	if err != nil {
		t.Fatalf("读取 manifest 失败: %v", err)
	}
	m, err := plugin.ParseManifest(data)
	if err != nil {
		t.Fatalf("解析 manifest 失败: %v", err)
	}
	return m
}

// TestManifestValid 断言 id 文法合法且整份清单通过 SDK 校验。
func TestManifestValid(t *testing.T) {
	m := loadManifest(t)
	if m.ID != "daedalus.snapshot" {
		t.Errorf("id = %q, want daedalus.snapshot", m.ID)
	}
	if !plugin.ValidID(m.ID) {
		t.Errorf("id 不符合插件 id 文法: %q", m.ID)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest 校验失败: %v", err)
	}
}

// TestManifestMatchesBinary 断言 tools/list 与 manifest.tools 集合相等。
func TestManifestMatchesBinary(t *testing.T) {
	m := loadManifest(t)
	session, ctx := connectSession(t)

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s 注解缺失或非只读", tool.Name)
		}
	}
	declared := slices.Clone(m.Tools)
	slices.Sort(names)
	slices.Sort(declared)
	if !slices.Equal(names, declared) {
		t.Errorf("tools/list = %v, manifest.tools = %v", names, declared)
	}
}

// TestManifestPermissionsMatchCode 断言 permissions.run 恰好等于候选表并集:
// 多声明会无谓放大沙箱授权面,少声明则沙箱内实际 exec 被拦、工具永久不可用。
// read/write 恒空(本插件不读任何文件内容,更不写)。
func TestManifestPermissionsMatchCode(t *testing.T) {
	m := loadManifest(t)
	if m.Permissions == nil {
		t.Fatal("缺少 permissions 字段")
	}
	var union []string
	for _, probe := range backendProbes {
		union = append(union, probe.Candidates...)
	}
	slices.Sort(union)
	declared := slices.Clone(m.Permissions.Run)
	slices.Sort(declared)
	if !slices.Equal(declared, union) {
		t.Errorf("permissions.run = %v, want 候选表并集 %v", declared, union)
	}
	if len(m.Permissions.Read) != 0 {
		t.Errorf("permissions.read = %v, want 空", m.Permissions.Read)
	}
	if len(m.Permissions.Write) != 0 {
		t.Errorf("permissions.write = %v, want 空", m.Permissions.Write)
	}
}

// TestNoWriteImports 是本包的只读闸:非测试源码里出现写/建/删符号即失败。
var forbiddenSymbols = regexp.MustCompile(
	`os\.(Remove|RemoveAll|WriteFile|Mkdir|MkdirAll|Rename|Chmod|OpenFile)|exec\.Command`)

func TestNoWriteImports(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("读取包目录失败: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", name, err)
		}
		scanned++
		for i, line := range strings.Split(string(data), "\n") {
			if loc := forbiddenSymbols.FindString(line); loc != "" {
				t.Errorf("%s:%d 出现禁用符号 %q: %s", name, i+1, loc, strings.TrimSpace(line))
			}
		}
	}
	if scanned == 0 {
		t.Fatal("未扫描到任何非测试源码,测试无效")
	}
}
