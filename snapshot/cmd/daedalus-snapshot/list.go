package main

import (
	"context"
	"fmt"
	"strings"
)

// snapshotEntry 是一条快照事实(ID 与人类可读名字)。
type snapshotEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// snapshotListIn 是 snapshot_list 的入参:backend 省略时用 recommended。
type snapshotListIn struct {
	Backend *string `json:"backend,omitempty"`
}

// rsyncBackend 是唯一没有快照注册表的后端:它只是文件拷贝兜底。
const rsyncBackend = "rsync"

// snapshotListPayload 组装 snapshot_list 回包。
//
// 三种结局刻意区分开:未知/不可用后端给空数组且 **不带** error(不可用不是
// 错误,下游不该为此重试);命令真执行失败给空数组 + error(失败必须可见);
// 成功给解析结果。snapshots 恒为数组,绝不为 null。
func snapshotListPayload(ctx context.Context, in snapshotListIn) map[string]any {
	backend := ""
	if in.Backend != nil {
		backend = strings.TrimSpace(*in.Backend)
	} else {
		_, recommended, _ := probeBackends(ctx, pathExists, execCommand)
		backend = recommended
	}
	if backend == "" {
		return emptySnapshotList("")
	}

	probe, ok := probeByName(backend)
	if !ok {
		return emptySnapshotList(backend)
	}
	available := firstExisting(probe.Candidates) != ""
	return snapshotPayload(ctx, probe, available, backend)
}

// snapshotPayload 对单个后端执行只读列举。
func snapshotPayload(ctx context.Context, probe backendProbe, available bool, backend string) map[string]any {
	if !available {
		return emptySnapshotList(backend)
	}
	// rsync 没有快照注册表:可用但无快照不是错误。
	if backend == rsyncBackend {
		return emptySnapshotList(backend)
	}

	binary := firstExisting(probe.Candidates)
	if binary == "" {
		return emptySnapshotList(backend)
	}
	args, parse := listCommand(backend)
	if parse == nil {
		return emptySnapshotList(backend)
	}

	execCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	stdout, stderr, code, err := execCommand(execCtx, binary, args)
	command := binary + " " + strings.Join(args, " ")

	switch {
	case err != nil:
		return failedSnapshotList(backend, command+" => exec 失败: "+err.Error())
	case code != 0:
		return failedSnapshotList(backend, fmt.Sprintf("%s => rc=%d: %s", command, code, firstLine(stderr)))
	}
	entries := parse(stdout)
	if entries == nil {
		entries = []snapshotEntry{}
	}
	return map[string]any{"backend": backend, "snapshots": entries}
}

// listCommand 给出后端对应的只读列举 argv 与解析器。三条命令都只读:
// btrfs subvolume list / lvs 查询 / snapper 列举,不含任何 create/delete/undo。
func listCommand(backend string) ([]string, func(string) []snapshotEntry) {
	switch backend {
	case "btrfs":
		// -o 只列该子卷下的快照;/ 是默认挂载点(本插件不接 mountpoint 入参)。
		return []string{"subvolume", "list", "-o", "/"}, parseBtrfsList
	case "lvm":
		return []string{"--noheadings", "--separator", "|", "-o", "lv_name,lv_attr,origin,snap_percent"}, parseLvmList
	case "snapper":
		return []string{"--csvout", "list", "-c", "root"}, parseSnapperCSV
	}
	return nil, nil
}

// emptySnapshotList 表达"没有可列举的快照":数组恒为空,不出现 error 键。
func emptySnapshotList(backend string) map[string]any {
	return map[string]any{"backend": backend, "snapshots": []snapshotEntry{}}
}

// failedSnapshotList 表达"命令确实跑过并失败":失败可见,但 snapshots 的类型不变。
func failedSnapshotList(backend, message string) map[string]any {
	return map[string]any{"backend": backend, "snapshots": []snapshotEntry{}, "error": message}
}

// probeByName 按名字取后端探测描述。
func probeByName(backend string) (backendProbe, bool) {
	for _, probe := range backendProbes {
		if probe.Name == backend {
			return probe, true
		}
	}
	return backendProbe{}, false
}

// firstExisting 按候选顺序取第一个存在的路径;不搜 PATH。
func firstExisting(candidates []string) string {
	for _, c := range candidates {
		if pathExists(c) {
			return c
		}
	}
	return ""
}

// parseBtrfsList 解析 `btrfs subvolume list` 输出:"ID <id> ... path <name>"。
// 只认以 ID 开头的行;没有 path 字段的行无法给出名字,跳过。
func parseBtrfsList(out string) []snapshotEntry {
	entries := []snapshotEntry{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ID ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		const marker = " path "
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}
		entries = append(entries, snapshotEntry{
			ID:   fields[1],
			Name: strings.TrimSpace(line[idx+len(marker):]),
		})
	}
	return entries
}

// parseLvmList 解析 `lvs --separator |` 输出:首列 lv_name、次列 lv_attr。
// 只有属性首字符为 s(快照)或 S(精简快照)的逻辑卷入选。LVM 快照没有描述,
// name 就用 lv_name —— 不臆造一个看起来像描述的字段。
func parseLvmList(out string) []snapshotEntry {
	entries := []snapshotEntry{}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "|")
		if len(cols) < 2 {
			continue
		}
		name := strings.TrimSpace(cols[0])
		attr := strings.TrimSpace(cols[1])
		if name == "" || attr == "" {
			continue
		}
		if attr[0] != 's' && attr[0] != 'S' {
			continue
		}
		entries = append(entries, snapshotEntry{ID: name, Name: name})
	}
	return entries
}

// parseSnapperCSV 解析 `snapper --csvout list` 输出。表头行按首列名识别,
// description 列按表头名定位(不同版本的列序不尽相同),定位不到时退回末列。
// 首列非数字的行不是数据行,跳过。
func parseSnapperCSV(out string) []snapshotEntry {
	entries := []snapshotEntry{}
	descriptionCol := -1
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cols := strings.Split(line, ",")
		for i := range cols {
			cols[i] = strings.TrimSpace(cols[i])
		}
		if len(cols) < 2 {
			continue
		}
		if strings.EqualFold(cols[0], "id") {
			descriptionCol = indexOfFold(cols, "description")
			continue
		}
		if !isDigits(cols[0]) {
			continue
		}
		name := cols[len(cols)-1]
		if descriptionCol >= 0 && descriptionCol < len(cols) {
			name = cols[descriptionCol]
		}
		entries = append(entries, snapshotEntry{ID: cols[0], Name: name})
	}
	return entries
}

func indexOfFold(cols []string, want string) int {
	for i, c := range cols {
		if strings.EqualFold(c, want) {
			return i
		}
	}
	return -1
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
