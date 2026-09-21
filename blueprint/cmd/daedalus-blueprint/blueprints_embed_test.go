package main

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/blueprint"
)

// TestEmbeddedBlueprints_Complete 验证嵌入的蓝图数据完整:
//  1. 6 个已知蓝图 × 4 个必需文件 = 24 个文件在位(经 init 校验,但测试显式
//     断言一次,失败信息含蓝图名 + 文件名);
//  2. 经 registry.MustLoad 加载成功,恰好返回 6 个蓝图(目录名 == id,
//     manifest 合法且 New 校验通过)。
func TestEmbeddedBlueprints_Complete(t *testing.T) {
	// 显式 6×4 文件完整性断言(与 init 同口径;独立复述,失败定位更清楚)。
	for _, id := range knownBlueprintIDs {
		for _, file := range requiredBlueprintFiles {
			if _, err := fs.Stat(embeddedRoot, id+"/"+file); err != nil {
				t.Errorf("嵌入数据缺蓝图 %q 的必需文件 %q: %v", id, file, err)
			}
		}
	}

	// 经真实 registry 加载:init 已保证 4 文件齐全,MustLoad 断言目录名==id
	// + manifest 合法 + New 校验通过,返回恰好 6 个。
	bs := blueprint.MustLoad(EmbeddedBlueprints())
	if len(bs) != len(knownBlueprintIDs) {
		t.Fatalf("加载蓝图数 = %d,期望 %d", len(bs), len(knownBlueprintIDs))
	}

	// 逐 id 核对:嵌入目录名与 manifest id 一致(registry 已校验),且 6 个
	// 蓝图 id 恰好覆盖 knownBlueprintIDs,无缺无余。
	got := make([]string, 0, len(bs))
	for _, b := range bs {
		got = append(got, b.ID)
	}
	joined := strings.Join(got, ",")
	for _, want := range knownBlueprintIDs {
		if !strings.Contains(joined, want) {
			t.Errorf("加载结果缺少蓝图 %q,实际: %v", want, got)
		}
	}
	if len(bs) != len(knownBlueprintIDs) {
		t.Fatalf("加载蓝图数 = %d,期望 %d", len(bs), len(knownBlueprintIDs))
	}
}
