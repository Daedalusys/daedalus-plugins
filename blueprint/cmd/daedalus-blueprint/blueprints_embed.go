// Package main 的 blueprints_embed.go(plan todo 15):把 6 个蓝图数据编入二进制。
//
// 嵌入方式(方案 D——构建期复制,go:embed 的唯一可行路径):
//
//	Go embed 不能引用模块目录之外的文件——`../..` 越界与符号链接均被 go 工具链
//	拒绝,而蓝图源码侧位于 daedalus-plugins/blueprint/blueprints/(在 blueprint
//	Go 模块之外)。因此构建期经 `just blueprint-embed`(rsync)把蓝图数据复制到
//	本目录 blueprints/ 下,再经 `//go:embed all:blueprints/*` 嵌入二进制。
//	复制产物不入库(见 daedalus-plugins/.gitignore),源码侧
//	daedalus-plugins/blueprint/blueprints/ 仍是唯一事实源。
//
// 嵌入命名:`all:blueprints/*` 的匹配前缀是 blueprints/ 之前的路径,故嵌入 FS
// 的根是 blueprints 目录本身,6 个蓝图目录在其下。经 embeddedRoot(fs.Sub)
// 剥掉 blueprints 前缀后,FS 根直接是 6 个蓝图目录(<id>/manifest.json 等),
// 与 internal/blueprint 的 registry.Load(fs.FS) 期望的"根下即蓝图目录"布局一致。
package main

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

// embeddedBlueprints 是嵌入的蓝图数据 FS(`all:blueprints/*` 嵌入全部文件;
// FS 根为 blueprints 目录)。
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

// init 做嵌入数据的完整性校验(fail-closed):遍历嵌入 FS,断言 6 个已知
// 蓝图 id 各自目录的 4 个必需文件全部在位,任一缺失即 panic,panic 信息
// 含缺失的蓝图名与文件名(便于排错)。
//
// 时机说明:这是"启动期"校验而非字面意义的编译期——`//go:embed` 的目录
// 匹配在 go build 阶段完成(blueprints/ 缺失会直接编译失败),文件级完整性
// 则在二进制启动 / go test 的 init 阶段断言。缺文件时构建产物根本不该带
// 上残缺数据,panic 优于静默降级(与 internal/blueprint.MustLoad 语义一致)。
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

// mustSubFS 用 fs.Sub 剥掉嵌入 FS 的 blueprints 前缀;失败(embed 布局
// 与预期不符)属不可恢复的初始化事故,直接 panic(fail-closed)。
func mustSubFS(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(fmt.Sprintf("blueprint: 嵌入 FS 缺少目录 %q: %v", dir, err))
	}
	return sub
}

// EmbeddedBlueprints 返回嵌入的蓝图数据 FS(根下即 6 个蓝图目录),
// 供 internal/blueprint 的 registry.Load / MustLoad 消费。
func EmbeddedBlueprints() fs.FS {
	return embeddedRoot
}
