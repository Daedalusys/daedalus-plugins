// snapshot_list 的行为测试:后端列举必须"不造假"——未知/不可用后端给空数组
// 而不是错误或假对象,真执行失败要可见但类型不变。
package main

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// listCommandArgs 返回某后端的只读列举 argv(测试据此断言调用序列)。
func listCommandArgs(backend string) []string {
	switch backend {
	case "btrfs":
		return []string{"subvolume", "list", "-o", "/"}
	case "lvm":
		return []string{"--noheadings", "--separator", "|", "-o", "lv_name,lv_attr,origin,snap_percent"}
	case "snapper":
		return []string{"--csvout", "list", "-c", "root"}
	}
	return nil
}

// TestProbeLvmSnapperRegistered 钉死插入 lvm/snapper 后的优先级顺序:
// btrfs ≫ lvm ≫ snapper ≫ rsync,rsync 不得因先写就排前面。
func TestProbeLvmSnapperRegistered(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{stdout: "v1.2.3", code: 0}}}
	stubSeams(t, fakePathSet("/usr/sbin/lvs", "/usr/bin/snapper"), fe)

	statuses, recommended, supportsRollback := probeBackends(context.Background(), pathExists, execCommand)
	var names []string
	for _, st := range statuses {
		names = append(names, st.Name)
	}
	if !slices.Equal(names, []string{"btrfs", "lvm", "snapper", "rsync"}) {
		t.Errorf("后端顺序 = %v, want [btrfs lvm snapper rsync]", names)
	}
	if recommended != "lvm" {
		t.Errorf("recommended = %q, want lvm", recommended)
	}
	if !supportsRollback {
		t.Error("有可用后端时 supports_rollback 应为 true")
	}
}

// TestListUnsupportedBackendReturnsEmpty 未知后端:空数组、无 error、零 exec。
func TestListUnsupportedBackendReturnsEmpty(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{code: 0}}}
	stubSeams(t, fakePathSet("/usr/bin/btrfs"), fe)

	backend := "zfs"
	out := snapshotListPayload(context.Background(), snapshotListIn{Backend: &backend})
	if out["backend"] != "zfs" {
		t.Errorf("backend = %v, want zfs", out["backend"])
	}
	list, ok := out["snapshots"].([]snapshotEntry)
	if !ok || len(list) != 0 {
		t.Fatalf("snapshots = %v, want 空数组", out["snapshots"])
	}
	if _, ok := out["error"]; ok {
		t.Errorf("未知后端不应有 error 键: %v", out["error"])
	}
	if len(fe.calls) != 0 {
		t.Errorf("未知后端仍执行了命令: %v", fe.calls)
	}
}

// TestListUnavailableBackendReturnsEmpty 后端不可用(候选路径全不存在):
// 空数组、无 error。
func TestListUnavailableBackendReturnsEmpty(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{code: 0}}}
	stubSeams(t, fakePathSet(), fe)

	backend := "btrfs"
	out := snapshotListPayload(context.Background(), snapshotListIn{Backend: &backend})
	list, ok := out["snapshots"].([]snapshotEntry)
	if !ok || len(list) != 0 {
		t.Fatalf("snapshots = %v, want 空数组", out["snapshots"])
	}
	if _, ok := out["error"]; ok {
		t.Errorf("不可用后端不应有 error 键: %v", out["error"])
	}
	if len(fe.calls) != 0 {
		t.Errorf("不可用后端仍执行了命令: %v", fe.calls)
	}
}

// TestListExecFailureKeepsEmptyArray 真执行失败:空数组(不是 null)+ error 非空。
func TestListExecFailureKeepsEmptyArray(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{
		stderr: "ERROR: not a btrfs filesystem",
		code:   1,
	}}}
	stubSeams(t, fakePathSet("/usr/bin/btrfs"), fe)

	backend := "btrfs"
	out := snapshotListPayload(context.Background(), snapshotListIn{Backend: &backend})
	list, ok := out["snapshots"].([]snapshotEntry)
	if !ok {
		t.Fatalf("snapshots = %v(%T), want 空数组而非 null", out["snapshots"], out["snapshots"])
	}
	if len(list) != 0 {
		t.Errorf("snapshots = %v, want 空", list)
	}
	if msg, _ := out["error"].(string); msg == "" {
		t.Errorf("error = %v, want 非空", out["error"])
	}
}

// TestParseBtrfsList 解析 btrfs subvolume list 的 ID/path 两列。
func TestParseBtrfsList(t *testing.T) {
	out := "ID 256 gen 30 top level 5 path @snapshots/root\n" +
		"ID 257 gen 31 top level 5 path <FS_TREE>/snap\n" +
		"\n"
	entries := parseBtrfsList(out)
	if len(entries) != 2 {
		t.Fatalf("解析结果 = %d 条, want 2: %+v", len(entries), entries)
	}
	if entries[0] != (snapshotEntry{ID: "256", Name: "@snapshots/root"}) {
		t.Errorf("entries[0] = %+v", entries[0])
	}
	if entries[1] != (snapshotEntry{ID: "257", Name: "<FS_TREE>/snap"}) {
		t.Errorf("entries[1] = %+v", entries[1])
	}
}

// TestParseLvmList 只有快照属性的逻辑卷入选,普通卷必须丢弃。
func TestParseLvmList(t *testing.T) {
	out := "rootvol|-wi-ao----|          |  \n" +
		"snap1|s|0|100.00\n" +
		"snap2|S|0|50.00\n"
	entries := parseLvmList(out)
	if len(entries) != 2 {
		t.Fatalf("解析结果 = %d 条, want 2: %+v", len(entries), entries)
	}
	if entries[0].ID != "snap1" || entries[1].ID != "snap2" {
		t.Errorf("id = %q/%q, want snap1/snap2", entries[0].ID, entries[1].ID)
	}
	for _, e := range entries {
		if e.Name != e.ID {
			t.Errorf("LVM 快照没有描述,name 应等于 lv_name: %+v", e)
		}
	}
}

// TestParseSnapperCSV 跳过表头,id 取首列,name 取 description 列。
func TestParseSnapperCSV(t *testing.T) {
	out := "ID,#,Date,Time,User,Cleanup,Description,Type\n" +
		"1,0,2026-11-01 10:00,10:00:00,root,default,daily snapshot,single\n" +
		"2,0,2026-11-02 10:00,10:00:00,root,default,weekly snapshot,single\n"
	entries := parseSnapperCSV(out)
	if len(entries) != 2 {
		t.Fatalf("解析结果 = %d 条, want 2: %+v", len(entries), entries)
	}
	if entries[0] != (snapshotEntry{ID: "1", Name: "daily snapshot"}) {
		t.Errorf("entries[0] = %+v", entries[0])
	}
	if entries[1].ID != "2" || entries[1].Name != "weekly snapshot" {
		t.Errorf("entries[1] = %+v", entries[1])
	}
}

// TestDefaultBackendUsesRecommended 省略 backend 时走 recommended 对应的后端,
// 且只执行只读 argv。
func TestDefaultBackendUsesRecommended(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{
		{stdout: "btrfs-progs v6.8", code: 0},
		{stdout: "ID 256 gen 30 top level 5 path @snapshots/root\n", code: 0},
	}}
	stubSeams(t, fakePathSet("/usr/bin/btrfs"), fe)

	out := snapshotListPayload(context.Background(), snapshotListIn{})
	if out["backend"] != "btrfs" {
		t.Errorf("backend = %v, want btrfs", out["backend"])
	}
	list, ok := out["snapshots"].([]snapshotEntry)
	if !ok || len(list) != 1 || list[0].ID != "256" {
		t.Fatalf("snapshots = %v", out["snapshots"])
	}
	var found bool
	for _, call := range fe.calls {
		if slices.Equal(call, append([]string{"/usr/bin/btrfs"}, listCommandArgs("btrfs")...)) {
			found = true
		}
	}
	if !found {
		t.Errorf("未执行 btrfs 只读列举命令: %v", fe.calls)
	}
	for _, call := range fe.calls {
		joined := strings.Join(call, " ")
		for _, forbidden := range []string{"snapshot", "delete", "subvolume", "undochange", "create"} {
			if forbidden == "subvolume" && strings.Contains(joined, "subvolume list") {
				continue
			}
			if strings.Contains(joined, forbidden) {
				t.Errorf("命令含变更类子命令 %q: %s", forbidden, joined)
			}
		}
	}
}

// TestRsyncHasNoRegistry rsync 可用但没有快照注册表:空数组、无 error。
func TestRsyncHasNoRegistry(t *testing.T) {
	fe := &fakeExec{steps: []fakeStep{{stdout: "rsync  version 3.2.7", code: 0}}}
	stubSeams(t, fakePathSet("/usr/bin/rsync"), fe)

	backend := "rsync"
	out := snapshotListPayload(context.Background(), snapshotListIn{Backend: &backend})
	list, ok := out["snapshots"].([]snapshotEntry)
	if !ok || len(list) != 0 {
		t.Fatalf("snapshots = %v, want 空数组", out["snapshots"])
	}
	if _, ok := out["error"]; ok {
		t.Errorf("rsync 无注册表不是错误: %v", out["error"])
	}
}
