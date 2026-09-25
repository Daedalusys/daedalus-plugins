// Package main 的 blueprints_embed.go:把 6 个蓝图数据编入二进制。
//
// go:embed 不能引用模块目录之外的文件(`../..` 越界与符号链接均被工具链拒绝),
// 而蓝图源码侧在 blueprint Go 模块之外;故构建期经 `just blueprint-embed`
// (rsync)复制到本目录 blueprints/ 再嵌入。复制产物不入库,源码侧仍是唯一事实源。
// `all:blueprints/*` 剥掉前缀后根下即 6 个蓝图目录,与 registry.Load 期望一致。
package main

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

// embeddedBlueprints 是嵌入的蓝图数据 FS(根为 blueprints 目录)。
//
//go:embed all:blueprints/*
var embeddedBlueprints embed.FS

// embeddedRoot 是去掉 blueprints 前缀后的蓝图 FS(根下即 6 个蓝图目录)。
// 包级变量按依赖序初始化,先于任何 init 运行。
var embeddedRoot fs.FS = mustSubFS(embeddedBlueprints, "blueprints")

// knownBlueprintIDs 是 v1 出厂自带的 6 个蓝图 id(fail-closed 校验清单)。
var knownBlueprintIDs = []string{
	"haproxy-backend",
	"nginx-reverse-proxy",
	"nginx-vhost",
	"postgres-db",
	"postgres-user",
	"redis-acl",
}

// requiredBlueprintFiles 是每个蓝图目录必须齐全的必需文件;其余文件
// (pre_check.sh / README.md 等)同样被嵌入,但不参与必需性校验。
var requiredBlueprintFiles = []string{
	"manifest.json",
	"schema.json",
	"template.tmpl",
	"post_check.sh",
}

// init 做嵌入数据的完整性校验(fail-closed):6 个已知蓝图 id × 4 必需文件全在位,
// 任一缺失即 panic(信息含缺失的蓝图名与文件名)。启动期校验而非编译期
// (`//go:embed` 只在 build 阶段匹配目录);panic 优于静默降级。
func init() {
	var missing []string
	for _, id := range knownBlueprintIDs {
		for _, file := range requiredBlueprintFiles {
			if _, err := fs.Stat(embeddedRoot, id+"/"+file); err != nil {
				missing = append(missing, id+"/"+file)
			}
		}
	}
	if len(missing) > 0 {
		panic(fmt.Sprintf(
			"blueprint: 嵌入蓝图数据不完整,缺失 %d 个必需文件: %s",
			len(missing), strings.Join(missing, ", ")))
	}
}

// mustSubFS 用 fs.Sub 剥掉嵌入 FS 的 blueprints 前缀;失败属不可恢复的初始化事故,直接 panic(fail-closed)。
func mustSubFS(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(fmt.Sprintf("blueprint: 嵌入 FS 缺少目录 %q: %v", dir, err))
	}
	return sub
}

// EmbeddedBlueprints 返回嵌入的蓝图 FS,供 internal/blueprint 的 registry.Load / MustLoad 消费。
func EmbeddedBlueprints() fs.FS {
	return embeddedRoot
}
