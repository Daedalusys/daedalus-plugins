// daedalus-dupe 的行为测试:直接驱动 scanLarge / scanDupes / applyPolicy 入口,
// 用真实临时目录演练三种查重算法、top_n 截断、min_size 过滤、pathguard 拒绝、
// ctx 取消与策略 fail-closed;另经内存内 MCP 握手固定 tools/list 注册形态。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/pathguard"
	"github.com/Daedalusys/daedalus-sdk/policy"
)

// connectSession 建立内存内客户端/服务器会话(镜像 fs 插件测试形态),
// 并在测试结束校验服务器随连接关闭而优雅退出。
func connectSession(t *testing.T) (*mcp.ClientSession, context.Context) {
	t.Helper()
	server := newServer()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "dupe-test-client", Version: "0.0.0"}, nil)
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

// TestToolsList_RegistersTwoReadOnlyTools 断言只注册 2 个只读工具,
// 注解形态与 manifest 的 tools 列表一致;可选参数经 omitempty 推断为非必填。
func TestToolsList_RegistersTwoReadOnlyTools(t *testing.T) {
	session, ctx := connectSession(t)
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	if len(res.Tools) != 2 {
		t.Fatalf("工具数量 = %d, want 2", len(res.Tools))
	}

	wantRequired := map[string][]string{
		"scan_large": {"dir"},
		"scan_dupes": {"algo", "dirs"},
	}
	wantProperties := map[string][]string{
		"scan_large": {"dir", "min_size", "top_n"},
		"scan_dupes": {"algo", "dirs", "min_size"},
	}

	byName := map[string]*mcp.Tool{}
	for _, tool := range res.Tools {
		byName[tool.Name] = tool
	}
	for name, required := range wantRequired {
		tool, ok := byName[name]
		if !ok {
			t.Errorf("缺少工具 %q", name)
			continue
		}
		a := tool.Annotations
		if a == nil {
			t.Fatalf("%s 无 Annotations", name)
		}
		if !a.ReadOnlyHint {
			t.Errorf("%s readOnlyHint = false, want true(L0 只读)", name)
		}
		if a.DestructiveHint == nil || *a.DestructiveHint {
			t.Errorf("%s destructiveHint 应为显式 false: %v", name, a.DestructiveHint)
		}
		if !a.IdempotentHint {
			t.Errorf("%s idempotentHint = false, want true", name)
		}
		if a.OpenWorldHint == nil || *a.OpenWorldHint {
			t.Errorf("%s openWorldHint 应为显式 false: %v", name, a.OpenWorldHint)
		}

		schema, ok := tool.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("%s inputSchema 类型异常: %T", name, tool.InputSchema)
		}
		gotRequired := schemaStringSlice(schema, "required")
		wantSorted := slices.Clone(required)
		slices.Sort(wantSorted)
		if !slices.Equal(gotRequired, wantSorted) {
			t.Errorf("%s required = %v, want %v", name, gotRequired, wantSorted)
		}
		props, ok := schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s properties 缺失: %v", name, schema["properties"])
		}
		names := make([]string, 0, len(props))
		for k := range props {
			names = append(names, k)
		}
		slices.Sort(names)
		wantProps := slices.Clone(wantProperties[name])
		slices.Sort(wantProps)
		if !slices.Equal(names, wantProps) {
			t.Errorf("%s properties = %v, want %v", name, names, wantProps)
		}
	}
}

// schemaStringSlice 提取 JSON Schema map 中某字符串数组字段(如 required)。
func schemaStringSlice(schema map[string]any, key string) []string {
	raw, ok := schema[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// mustTempDir 在白名单目录 /tmp 下创建隔离临时目录并注册清理。
func mustTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "daedalus-dupe-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("解析临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(real) })
	return real
}

// ensureDefaultAllowlist 把白名单固定为内置默认值,隔离策略类测试的全局注入,
// 并在用例结束恢复原值,保证扫描类测试可独立复跑。
func ensureDefaultAllowlist(t *testing.T) {
	t.Helper()
	orig := slices.Clone(pathguard.AllowedDirs)
	pathguard.WithAllowedDirs([]string{"/home", "/var/log", "/tmp"})
	t.Cleanup(func() { pathguard.WithAllowedDirs(orig) })
}

// writeSizedFile 在 dir 下创建 name,内容为 size 字节(体积是唯一断言对象)。
func writeSizedFile(t *testing.T, dir, name string, size int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0o644); err != nil {
		t.Fatalf("创建测试文件 %s 失败: %v", path, err)
	}
	return path
}

// writeFileContent 在 dir 下创建 name,写入逐字内容。
func writeFileContent(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("创建测试文件 %s 失败: %v", path, err)
	}
	return path
}

// resultText 取出单文本块内容;工具错误同样以 text 承载。
func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("结果内容块数量 = %d, want 1", len(res.Content))
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("结果内容块类型 = %T, want *mcp.TextContent", res.Content[0])
	}
	return text.Text
}

// decodeEntries 把 scan_large 的 JSON 文本解码为 largeEntry 列表。
func decodeEntries(t *testing.T, res *mcp.CallToolResult) []largeEntry {
	t.Helper()
	var entries []largeEntry
	if err := json.Unmarshal([]byte(resultText(t, res)), &entries); err != nil {
		t.Fatalf("scan_large 输出不是合法 JSON: %v", err)
	}
	return entries
}

// decodeGroups 把 scan_dupes 的 JSON 文本解码为 dupeGroup 列表。
func decodeGroups(t *testing.T, res *mcp.CallToolResult) []dupeGroup {
	t.Helper()
	var groups []dupeGroup
	if err := json.Unmarshal([]byte(resultText(t, res)), &groups); err != nil {
		t.Fatalf("scan_dupes 输出不是合法 JSON: %v", err)
	}
	return groups
}

func TestScanLarge_TopN(t *testing.T) {
	ensureDefaultAllowlist(t)
	base := mustTempDir(t)

	sizes := map[string]int{"a.txt": 10, "b.txt": 20, "c.txt": 30, "d.txt": 40, "e.txt": 50}
	for name, size := range sizes {
		writeSizedFile(t, base, name, size)
	}

	res, _, err := scanLarge(context.Background(), nil, ScanLargeInput{Dir: base, TopN: 3})
	if err != nil {
		t.Fatalf("scan_large 返回错误: %v", err)
	}
	if res.IsError {
		t.Fatalf("scan_large 工具错误: %s", resultText(t, res))
	}

	entries := decodeEntries(t, res)
	if len(entries) != 3 {
		t.Fatalf("top_n=3 应返回 3 条, got %d: %+v", len(entries), entries)
	}
	wantOrder := []string{"e.txt", "d.txt", "c.txt"}
	for i, entry := range entries {
		name := filepath.Base(entry.Path)
		if name != wantOrder[i] {
			t.Errorf("第 %d 条 = %s, want %s(应按体积降序)", i, name, wantOrder[i])
		}
		if entry.Size != int64(sizes[wantOrder[i]]) {
			t.Errorf("%s size = %d, want %d", name, entry.Size, sizes[wantOrder[i]])
		}
		if entry.Type != "file" {
			t.Errorf("%s type = %q, want %q", name, entry.Type, "file")
		}
		if _, err := time.Parse(time.RFC3339, entry.MTime); err != nil {
			t.Errorf("%s mtime 不是 RFC3339: %q", name, entry.MTime)
		}
	}
	if entries[0].Size < entries[1].Size || entries[1].Size < entries[2].Size {
		t.Errorf("结果未按体积降序: %+v", entries)
	}

	// 同一目录不截断时 5 个文件全部返回,证明是 top_n 截断而非漏扫。
	res, _, err = scanLarge(context.Background(), nil, ScanLargeInput{Dir: base})
	if err != nil || res.IsError {
		t.Fatalf("scan_large 默认 top_n 调用失败: err=%v res=%v", err, res)
	}
	if all := decodeEntries(t, res); len(all) != 5 {
		t.Errorf("默认 top_n 应返回全部 5 个文件, got %d", len(all))
	}
}

func TestScanLarge_MinSize(t *testing.T) {
	ensureDefaultAllowlist(t)
	base := mustTempDir(t)

	for _, name := range []string{"s1.bin", "s2.bin", "s3.bin", "s4.bin"} {
		writeSizedFile(t, base, name, 100)
	}
	const oneMiB = 1 << 20
	large := map[string]int{
		"l1.bin": oneMiB + 1,
		"l2.bin": oneMiB + 1024,
		"l3.bin": 2 * oneMiB,
	}
	for name, size := range large {
		writeSizedFile(t, base, name, size)
	}

	res, _, err := scanLarge(context.Background(), nil, ScanLargeInput{Dir: base, MinSize: oneMiB})
	if err != nil || res.IsError {
		t.Fatalf("scan_large 失败: err=%v res=%v", err, res)
	}
	entries := decodeEntries(t, res)
	if len(entries) != 3 {
		t.Fatalf("min_size=1MiB 应只返回 3 个达标文件, got %d: %+v", len(entries), entries)
	}
	for _, entry := range entries {
		if entry.Size < oneMiB {
			t.Errorf("%s size = %d, 低于 min_size 却出现在结果中", entry.Path, entry.Size)
		}
		if want, ok := large[filepath.Base(entry.Path)]; !ok || int64(want) != entry.Size {
			t.Errorf("意外条目 %s(size=%d)", entry.Path, entry.Size)
		}
	}
}

func TestScanLarge_EmptyDir(t *testing.T) {
	ensureDefaultAllowlist(t)
	base := mustTempDir(t)

	res, _, err := scanLarge(context.Background(), nil, ScanLargeInput{Dir: base})
	if err != nil || res.IsError {
		t.Fatalf("scan_large 空目录失败: err=%v res=%v", err, res)
	}
	if text := resultText(t, res); text != "[]" {
		t.Errorf("空目录输出 = %q, want %q", text, "[]")
	}
	if entries := decodeEntries(t, res); len(entries) != 0 {
		t.Errorf("空目录应返回空列表, got %+v", entries)
	}
}

func TestScanLarge_PathGuardRejectsRoot(t *testing.T) {
	ensureDefaultAllowlist(t)
	res, _, err := scanLarge(context.Background(), nil, ScanLargeInput{Dir: "/etc"})
	if err != nil {
		t.Fatalf("pathguard 拒绝应以工具错误返回,而非传输错误: %v", err)
	}
	if !res.IsError {
		t.Fatalf("/etc 竟然通过白名单: %s", resultText(t, res))
	}
	text := resultText(t, res)
	if !strings.HasPrefix(text, "Error: ") || !strings.Contains(text, "outside allowed directories") {
		t.Errorf("pathguard 错误形态漂移: %q", text)
	}
}

func TestScanLarge_CtxCancel(t *testing.T) {
	ensureDefaultAllowlist(t)
	base := mustTempDir(t)
	for i := 0; i < 20; i++ {
		writeSizedFile(t, base, "f"+strings.Repeat("0", 2)+string(rune('a'+i))+".bin", 64)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 进入遍历前即取消,断言取消信号确定性传播。

	res, _, err := scanLarge(ctx, nil, ScanLargeInput{Dir: base, MinSize: 0, TopN: 5})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后应返回 context.Canceled, got err=%v", err)
	}
	if res != nil {
		t.Errorf("取消后不应返回结果: %+v", res)
	}
}

func TestScanDupes_SizeOnly(t *testing.T) {
	ensureDefaultAllowlist(t)
	base := mustTempDir(t)
	sub := filepath.Join(base, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	a := writeSizedFile(t, base, "a.bin", 1500)
	b := writeSizedFile(t, sub, "b.bin", 1500)
	c := writeSizedFile(t, base, "c.bin", 300)
	d := writeSizedFile(t, base, "d.bin", 300)
	unique := writeSizedFile(t, base, "e.bin", 7)

	res, _, err := scanDupes(context.Background(), nil, ScanDupesInput{Dirs: []string{base}, Algo: algoSizeOnly})
	if err != nil || res.IsError {
		t.Fatalf("scan_dupes size_only 失败: err=%v res=%v", err, res)
	}
	groups := decodeGroups(t, res)
	if len(groups) != 2 {
		t.Fatalf("size 重复应产生 2 组, got %d: %+v", len(groups), groups)
	}

	cross := groups[0]
	if cross.GroupID != "size-1500" || cross.WastedBytes != 1500 {
		t.Errorf("跨目录组异常: %+v", cross)
	}
	if cross.SameDir {
		t.Errorf("a.bin 与 sub/b.bin 跨目录,same_dir 应为 false: %+v", cross)
	}
	if !slices.Equal(cross.Files, []string{a, b}) {
		t.Errorf("跨目录组文件 = %v, want [%s %s]", cross.Files, a, b)
	}

	same := groups[1]
	if same.GroupID != "size-300" || same.WastedBytes != 300 {
		t.Errorf("同目录组异常: %+v", same)
	}
	if !same.SameDir {
		t.Errorf("c.bin 与 d.bin 同目录,same_dir 应为 true: %+v", same)
	}
	if !slices.Equal(same.Files, []string{c, d}) {
		t.Errorf("同目录组文件 = %v, want [%s %s]", same.Files, c, d)
	}

	for _, group := range groups {
		if slices.Contains(group.Files, unique) {
			t.Errorf("体积唯一的 e.bin 不得出现在重复组: %+v", group)
		}
	}
}

func TestScanDupes_First1MB(t *testing.T) {
	ensureDefaultAllowlist(t)
	base := mustTempDir(t)

	// dup1/dup2 共享前 1 MiB 但尾部不同:体积相同、全文不同,
	// 只有 first_1mb 会把它们归为一组,sha256 不会(下条断言固定)。
	prefix := strings.Repeat("P", firstChunkSize)
	dup1 := writeFileContent(t, base, "dup1.bin", prefix+"AAAA")
	dup2 := writeFileContent(t, base, "dup2.bin", prefix+"BBBB")
	writeFileContent(t, base, "other1.bin", "hello")
	writeFileContent(t, base, "other2.bin", "hello-daedalus")

	res, _, err := scanDupes(context.Background(), nil, ScanDupesInput{Dirs: []string{base}, Algo: algoFirst1MB})
	if err != nil || res.IsError {
		t.Fatalf("scan_dupes first_1mb 失败: err=%v res=%v", err, res)
	}
	groups := decodeGroups(t, res)
	if len(groups) != 1 {
		t.Fatalf("first_1mb 应产生 1 组, got %d: %+v", len(groups), groups)
	}
	group := groups[0]
	if !strings.HasPrefix(group.GroupID, "first1mb-") {
		t.Errorf("组 ID 前缀 = %q, want first1mb-", group.GroupID)
	}
	if !slices.Equal(group.Files, []string{dup1, dup2}) {
		t.Errorf("组文件 = %v, want [%s %s]", group.Files, dup1, dup2)
	}
	if want := int64(firstChunkSize + 4); group.WastedBytes != want {
		t.Errorf("wasted_bytes = %d, want %d", group.WastedBytes, want)
	}
	if !group.SameDir {
		t.Errorf("dup1/dup2 同目录,same_dir 应为 true: %+v", group)
	}

	// 同一夹具换 sha256:全文不同 → 没有重复组(证明算法分支真实生效)。
	res, _, err = scanDupes(context.Background(), nil, ScanDupesInput{Dirs: []string{base}, Algo: algoSHA256})
	if err != nil || res.IsError {
		t.Fatalf("scan_dupes sha256 复跑失败: err=%v res=%v", err, res)
	}
	if groups := decodeGroups(t, res); len(groups) != 0 {
		t.Errorf("全文不同的前缀碰撞文件不应被 sha256 归组: %+v", groups)
	}
}

func TestScanDupes_SHA256(t *testing.T) {
	ensureDefaultAllowlist(t)
	base := mustTempDir(t)

	payload := "daedalus-dupe-payload"
	same1 := writeFileContent(t, base, "same1.bin", payload)
	same2 := writeFileContent(t, base, "same2.bin", payload)
	writeFileContent(t, base, "diff1.bin", "payload-one")
	writeFileContent(t, base, "diff2.bin", "payload-two-longer")

	res, _, err := scanDupes(context.Background(), nil, ScanDupesInput{Dirs: []string{base}, Algo: algoSHA256})
	if err != nil || res.IsError {
		t.Fatalf("scan_dupes sha256 失败: err=%v res=%v", err, res)
	}
	groups := decodeGroups(t, res)
	if len(groups) != 1 {
		t.Fatalf("sha256 应产生 1 组, got %d: %+v", len(groups), groups)
	}
	group := groups[0]
	if !strings.HasPrefix(group.GroupID, "sha256-") {
		t.Errorf("组 ID 前缀 = %q, want sha256-", group.GroupID)
	}
	if !slices.Equal(group.Files, []string{same1, same2}) {
		t.Errorf("组文件 = %v, want [%s %s]", group.Files, same1, same2)
	}
	if want := int64(len(payload)); group.WastedBytes != want {
		t.Errorf("wasted_bytes = %d, want %d", group.WastedBytes, want)
	}
	if !group.SameDir {
		t.Errorf("same1/same2 同目录,same_dir 应为 true: %+v", group)
	}
}

func TestScanDupes_UnknownAlgo(t *testing.T) {
	ensureDefaultAllowlist(t)
	base := mustTempDir(t)
	writeSizedFile(t, base, "a.bin", 32)

	res, _, err := scanDupes(context.Background(), nil, ScanDupesInput{Dirs: []string{base}, Algo: "md5"})
	if err != nil {
		t.Fatalf("未知算法应以工具错误返回,而非传输错误: %v", err)
	}
	if !res.IsError {
		t.Fatalf("未知算法 md5 竟然成功: %s", resultText(t, res))
	}
	want := `unknown algo "md5" (supported: size_only|first_1mb|sha256)`
	if text := resultText(t, res); !strings.Contains(text, want) {
		t.Errorf("错误消息 = %q, want 含 %q", text, want)
	}
}

func TestScanDupes_PathGuardRejects(t *testing.T) {
	ensureDefaultAllowlist(t)
	res, _, err := scanDupes(context.Background(), nil, ScanDupesInput{Dirs: []string{"/etc"}, Algo: algoSizeOnly})
	if err != nil {
		t.Fatalf("pathguard 拒绝应以工具错误返回,而非传输错误: %v", err)
	}
	if !res.IsError || !strings.Contains(resultText(t, res), "outside allowed directories") {
		t.Errorf("/etc 未被白名单拒绝: isError=%v text=%q", res.IsError, resultText(t, res))
	}
}

func TestScanDupes_MinSizeFilter(t *testing.T) {
	ensureDefaultAllowlist(t)
	base := mustTempDir(t)
	for _, name := range []string{"a.bin", "b.bin", "c.bin", "d.bin", "e.bin"} {
		writeSizedFile(t, base, name, 10)
	}

	res, _, err := scanDupes(context.Background(), nil, ScanDupesInput{
		Dirs:    []string{base},
		MinSize: 100 << 20, // 100 MiB:全部文件被过滤。
		Algo:    algoSizeOnly,
	})
	if err != nil || res.IsError {
		t.Fatalf("scan_dupes min_size 过滤失败: err=%v res=%v", err, res)
	}
	if text := resultText(t, res); text != "[]" {
		t.Errorf("全被过滤时输出 = %q, want %q", text, "[]")
	}
	if groups := decodeGroups(t, res); len(groups) != 0 {
		t.Errorf("min_size 过滤后不应有分组: %+v", groups)
	}
}

// —— 策略接线(fail-closed)——

func TestApplyPolicyCorrupt(t *testing.T) {
	orig := slices.Clone(pathguard.AllowedDirs)
	t.Cleanup(func() { pathguard.WithAllowedDirs(orig) })

	t.Setenv(policy.EnvPolicyPath, filepath.Join("testdata", "corrupt.toml"))
	if err := applyPolicy(); err == nil {
		t.Fatal("损坏策略竟然加载成功(应 fail-closed 拒绝启动)")
	}
	if !slices.Equal(pathguard.AllowedDirs, orig) {
		t.Errorf("损坏策略不得部分注入白名单: %v", pathguard.AllowedDirs)
	}
}

func TestApplyPolicyMissing(t *testing.T) {
	orig := slices.Clone(pathguard.AllowedDirs)
	t.Cleanup(func() { pathguard.WithAllowedDirs(orig) })

	t.Setenv(policy.EnvPolicyPath, filepath.Join(t.TempDir(), "absent.toml"))
	if err := applyPolicy(); err == nil {
		t.Fatal("显式指向缺失策略应报错(不得静默回退)")
	}

	t.Setenv(policy.EnvPolicyPath, filepath.Join("testdata", "policy.toml"))
	if err := applyPolicy(); err != nil {
		t.Fatalf("加载 testdata 合法策略失败: %v", err)
	}
	if !slices.Equal(pathguard.AllowedDirs, []string{"/tmp"}) {
		t.Fatalf("allowed_dirs 未跟随夹具: %v", pathguard.AllowedDirs)
	}

	t.Setenv(policy.EnvPolicyPath, "")
	if _, err := os.Stat(policy.ProductionPath); err == nil {
		t.Skip("本机存在生产策略,跳过缺失回退演练")
	}
	t.Chdir(t.TempDir()) // 空目录上溯不可能命中仓库回溯路径(含 testdata 夹具)。
	if err := applyPolicy(); err != nil {
		t.Fatalf("策略全缺失应回退 Default 并成功: %v", err)
	}
	if !slices.Equal(pathguard.AllowedDirs, []string{"/home", "/var/log", "/tmp"}) {
		t.Errorf("Default 回退后白名单异常: %v", pathguard.AllowedDirs)
	}
}
