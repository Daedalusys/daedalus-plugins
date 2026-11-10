// filesystem_info 的解析与行为测试:挂载点来源只有 /proc/self/mountinfo,
// 夹具通过 readFile seam 注入,单测永不读取宿主 /proc。
package main

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mountInfoFixture 覆盖三类行:普通 ext4 根、带 \040 空格的挂载点、
// 无 source 语义的 overlay,以及一行缺 " - " 分隔的畸形行。
const mountInfoFixture = `36 35 98:0 / / rw,relatime - ext4 /dev/sda1 rw
37 36 0:32 / /mnt/with\040space rw,nosuid - overlay overlay rw,lowerdir=/a:/b
38 36 0:33 / /data rw - xfs /dev/sdb1 rw
1 2 3:4 / /malformed rw,relatime
`

func TestParseMountInfo(t *testing.T) {
	entries := parseMountInfo([]byte(mountInfoFixture))
	if len(entries) != 3 {
		t.Fatalf("解析结果 = %d 条, want 3(畸形行必须跳过): %+v", len(entries), entries)
	}
	if entries[0] != (mountEntry{Mountpoint: "/", Device: "/dev/sda1", Fstype: "ext4"}) {
		t.Errorf("entries[0] = %+v", entries[0])
	}
	if entries[1] != (mountEntry{Mountpoint: "/mnt/with space", Device: "overlay", Fstype: "overlay"}) {
		t.Errorf("entries[1] = %+v(\\040 应还原为空格)", entries[1])
	}
	if entries[2] != (mountEntry{Mountpoint: "/data", Device: "/dev/sdb1", Fstype: "xfs"}) {
		t.Errorf("entries[2] = %+v", entries[2])
	}
}

// TestUnescapeMountField 只还原 POSIX octal 转义,其余反斜杠序列原样保留。
func TestUnescapeMountField(t *testing.T) {
	cases := map[string]string{
		`/mnt/with\040space`: "/mnt/with space",
		`/mnt/tab\011here`:   "/mnt/tab\there",
		`/mnt/back\134slash`: `/mnt/back\slash`,
		`/mnt/keep\q`:        `/mnt/keep\q`,
	}
	for in, want := range cases {
		if got := unescapeMountField(in); got != want {
			t.Errorf("unescapeMountField(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFilesystemDefaultRoot 省略入参时只查根挂载点。
func TestFilesystemDefaultRoot(t *testing.T) {
	out := filesystemPayload([]byte(mountInfoFixture), nil)
	list, ok := out["mountpoints"].([]mountEntry)
	if !ok || len(list) != 1 {
		t.Fatalf("mountpoints = %v, want 单条 /", out["mountpoints"])
	}
	if list[0].Mountpoint != "/" || list[0].Fstype != "ext4" {
		t.Errorf("默认根挂载 = %+v", list[0])
	}
	if _, ok := out["error"]; ok {
		t.Errorf("正常回包不应带 error: %v", out["error"])
	}
}

// TestFilesystemUnknownMountpoint 未命中的挂载点一次性报全,且不返回半份结果。
func TestFilesystemUnknownMountpoint(t *testing.T) {
	out := filesystemPayload([]byte(mountInfoFixture), []string{"/", "/missing", "/gone"})
	if _, ok := out["mountpoints"]; ok {
		t.Errorf("有未命中项时不应给 mountpoints: %v", out)
	}
	if out["error"] != "未知挂载点: /missing /gone" {
		t.Errorf("error = %v", out["error"])
	}
}

// TestFilesystemIllegalInput 空串与控制字符在拼路径前拒绝,不 panic。
func TestFilesystemIllegalInput(t *testing.T) {
	for _, requested := range [][]string{{""}, {"/tmp\x00evil"}, {"/a\nb"}} {
		out := filesystemPayload([]byte(mountInfoFixture), requested)
		if _, ok := out["error"]; !ok {
			t.Errorf("入参 %q 应被拒绝: %v", requested, out)
		}
	}
}

// TestFilesystemStackedMountTakesLast 同一挂载点出现多次时取最后一条:
// mountinfo 按挂载顺序追加,后出现者是当前可见挂载。
func TestFilesystemStackedMountTakesLast(t *testing.T) {
	source := `36 35 98:0 / / rw - btrfs /dev/sda1 rw
99 36 0:40 / / rw - overlay overlay rw
`
	out := filesystemPayload([]byte(source), []string{"/"})
	list, ok := out["mountpoints"].([]mountEntry)
	if !ok || len(list) != 1 {
		t.Fatalf("mountpoints = %v", out["mountpoints"])
	}
	if list[0].Fstype != "overlay" || list[0].Device != "overlay" {
		t.Errorf("应取最后一条挂载 = %+v", list[0])
	}
}

// TestFilesystemRequestedOrderPreserved 结果顺序跟请求顺序一致,便于调用方对齐。
func TestFilesystemRequestedOrderPreserved(t *testing.T) {
	out := filesystemPayload([]byte(mountInfoFixture), []string{"/data", "/"})
	list, ok := out["mountpoints"].([]mountEntry)
	if !ok {
		t.Fatalf("mountpoints = %v", out["mountpoints"])
	}
	if got := []string{list[0].Mountpoint, list[1].Mountpoint}; !slices.Equal(got, []string{"/data", "/"}) {
		t.Errorf("结果顺序 = %v, want 请求顺序", got)
	}
}

// TestSeamsAreInjectable 是 seam 完整性的守门测试:os_state 的路径探测必须
// 全部落在固定候选表内(证明没有 PATH 搜索),filesystem_info 的内容读取必须
// 走 readFile seam(证明单测不会读宿主 /proc)。
func TestSeamsAreInjectable(t *testing.T) {
	var probed []string
	stubPathExists(t, func(p string) bool {
		probed = append(probed, p)
		return p == "/usr/bin/dnf"
	})
	root := t.TempDir()
	writeOSRelease(t, root, "ID=test\n")
	stubSysinfoRoot(t, root)
	_ = osStatePayload(newSysinfoService("/").OSRelease())

	allowed := map[string]bool{initSystemdPath: true}
	for _, cand := range packageManagerCandidates {
		for _, p := range cand.Paths {
			allowed[p] = true
		}
	}
	if len(probed) == 0 {
		t.Fatal("os_state 未做任何存在性探测")
	}
	for _, p := range probed {
		if !allowed[p] {
			t.Errorf("探测了候选表之外的路径 %q(禁止 PATH 搜索)", p)
		}
	}
	if !slices.Contains(probed, initSystemdPath) {
		t.Errorf("未探测 init 标志路径 %q: %v", initSystemdPath, probed)
	}

	var readPaths []string
	oldReadFile := readFile
	readFile = func(p string) ([]byte, error) {
		readPaths = append(readPaths, p)
		return []byte(mountInfoFixture), nil
	}
	t.Cleanup(func() { readFile = oldReadFile })

	session, ctx := connectSession(t)
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "filesystem_info",
		Arguments: map[string]any{"mountpoints": []string{"/data"}},
	})
	if err != nil {
		t.Fatalf("tools/call filesystem_info 传输失败: %v", err)
	}
	if res.IsError || len(res.Content) == 0 {
		t.Fatalf("filesystem_info 回包异常: %+v", res)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("回包非文本: %T", res.Content[0])
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("回包非 JSON: %v (%q)", err, text.Text)
	}
	list, ok := out["mountpoints"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("mountpoints = %v", out["mountpoints"])
	}
	if got := list[0].(map[string]any); got["mountpoint"] != "/data" || got["fstype"] != "xfs" {
		t.Errorf("mountpoint 事实 = %v", got)
	}
	if !slices.Equal(readPaths, []string{mountInfoPath}) {
		t.Errorf("读取路径 = %v, want [%s]", readPaths, mountInfoPath)
	}
}
