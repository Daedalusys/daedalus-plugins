// Package classify 按扩展名 + MIME 头把文件归入固定 category 集合。
//
// 数据来源: rules.json(//go:embed 注入构建期)。Type 优先用扩展名查表,
// 命中失败时用 mime.TypeByExtension 做兜底命中(只识别 image/ video/ audio
// 三大媒体类,其它一律 "other")。两条路径都失败 → "other",这是 daemon 决策
// 的兜底面,不是错误。
package classify

import (
	_ "embed"
	"encoding/json"
	"mime"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed rules.json
var rulesJSON []byte

// indexInit 把 rules.json 解码为 ext → category 倒排索引,初始化只跑一次。
// 解码失败时直接 panic: 这是构建期注入的合法 JSON,失败只能是构建被破坏。
var (
	indexOnce sync.Once
	index     map[string]string
	indexErr  error
)

func buildIndex() {
	idx := make(map[string]string)
	var rules map[string][]string
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		indexErr = err
		return
	}
	for category, exts := range rules {
		for _, raw := range exts {
			ext := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(raw), "."))
			if ext == "" {
				continue
			}
			idx[ext] = category
		}
	}
	index = idx
}

// Type 返回 path 的 category;无扩展名或未知扩展名 → "other",nil。
// 任何 category 解析都走这张索引,不在调用点旁路判断(避免语义漂移)。
func Type(path string) (string, error) {
	indexOnce.Do(buildIndex)
	if indexErr != nil {
		return "", indexErr
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	if ext == "" {
		return "other", nil
	}
	if cat, ok := index[ext]; ok {
		return cat, nil
	}
	if cat := categoryFromMIME(ext); cat != "" {
		return cat, nil
	}
	return "other", nil
}

// categoryFromMIME 用系统 mime 表补判:仅在扩展名查表未命中时启用,只信任
// 顶级类型是 image/ video/ audio 的命中(application/ 等不归类,避免把
// 未知扩展名误判为 archives / documents)。
func categoryFromMIME(ext string) string {
	mt := mime.TypeByExtension("." + ext)
	if mt == "" {
		return ""
	}
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = strings.TrimSpace(mt[:i])
	}
	switch {
	case strings.HasPrefix(mt, "image/"):
		return "images"
	case strings.HasPrefix(mt, "video/"):
		return "videos"
	case strings.HasPrefix(mt, "audio/"):
		return "music"
	}
	return ""
}
