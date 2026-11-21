// grants.go —— 只读面:tx_grants 列出「当前执行者手上能用的条子」。
//
// 只列绑定到执行者的条子:把别人的条子列出来,等于把越权者的目录还给他。
// 坏文件单独进 invalid[],一条坏文件不该挡住整张清单;过期的条子照列并标
// expired —— 隐藏它们会让 agent 以为「根本没条子」,而真实处置是「该请人续签」。
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Daedalusys/daedalus-sdk/grant"
)

// toolGrants 与 manifest.tools 逐字一致,同时是审计链里的 tool 字段。
const toolGrants = "tx_grants"

// grantBrief 是一张「当前执行者可用」条子的摘要。tx_grants 与拒绝体的
// available_grants 共用它:两处各拼一份形状,迟早会漂移。
type grantBrief struct {
	ID        string   `json:"id"`
	Scope     []string `json:"scope"`
	ExpiresAt string   `json:"expires_at"`
	MaxUses   int      `json:"max_uses"`
	Used      int      `json:"used"`
	Remaining int      `json:"remaining"`
	Expired   bool     `json:"expired"`
}

// grantInvalidEntry 是「这条条子文件坏了」的证词:坏文件不挡清单,但不能被静默吞掉。
type grantInvalidEntry struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

// executorView 让 agent 知道自己是以哪个身份在问:清单里的条目只对这一个身份成立。
type executorView struct {
	UID  uint32 `json:"uid"`
	Name string `json:"name"`
}

type grantsView struct {
	Executor executorView        `json:"executor"`
	Grants   []grantBrief        `json:"grants"`
	Invalid  []grantInvalidEntry `json:"invalid"`
}

// listUsableGrants 是 tx_grants 与拒绝体的唯一枚举源。usable 只含绑定到当前
// 执行者的条子;invalid 收集解析失败与 id 不符的坏文件。目录读不了或账本不可读
// 时返回 error:那时候给出的 used/remaining 不可信,不如不给。
func listUsableGrants() (usable []grantBrief, invalid []grantInvalidEntry, err error) {
	usable = []grantBrief{}
	invalid = []grantInvalidEntry{}

	dir := grantsDir()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		// 全新机器还没签过条子:空清单,不是错误。
		return usable, invalid, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("读条子目录 %s 失败: %v", dir, err)
	}

	// 用量取执行者自己的账本,且与判定共用同一份折叠结果:另读一份文件
	// 会让清单里的 remaining 与真正判上限的计数对不上。
	counts, err := grantUsage.snapshot()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		ownerUID, ownerName, data, readErr := readGrantFile(filepath.Join(dir, name))
		if errors.Is(readErr, os.ErrNotExist) {
			// 枚举与读取之间被撤销(撤销 = 删文件):那不是坏文件。
			continue
		}
		if readErr != nil {
			invalid = append(invalid, grantInvalidEntry{File: name, Error: shortErrText(readErr)})
			continue
		}
		g, parseErr := grant.Parse(data)
		if parseErr != nil {
			invalid = append(invalid, grantInvalidEntry{File: name, Error: shortErrText(parseErr)})
			continue
		}
		if g.ID != id {
			invalid = append(invalid, grantInvalidEntry{
				File:  name,
				Error: fmt.Sprintf("文件内 id=%q 与文件名不符", g.ID),
			})
			continue
		}
		// 绑定不通过的一律不列 —— 连"它存在"都不告诉越权者。
		if bindErr := grant.BindExecutor(g, ownerUID, ownerName, executorUID, executorName); bindErr != nil {
			continue
		}
		used := counts[g.ID]
		remaining := g.MaxUses - used
		if remaining < 0 {
			remaining = 0
		}
		usable = append(usable, grantBrief{
			ID:        g.ID,
			Scope:     g.Scope,
			ExpiresAt: g.ExpiresAt.UTC().Format(time.RFC3339),
			MaxUses:   g.MaxUses,
			Used:      used,
			Remaining: remaining,
			Expired:   g.Expired(now),
		})
	}
	return usable, invalid, nil
}

// txGrants 是 tx_grants 的处理体:零写入(只读条子目录与自己的账本),只落一条审计。
func txGrants() (grantsView, *structuredError) {
	usable, invalid, err := listUsableGrants()
	if err != nil {
		recordAudit(toolGrants, "error", map[string]any{"error": codeGrantUsageFailed}, nil)
		return grantsView{}, &structuredError{Error: codeGrantUsageFailed, Detail: shortErrText(err)}
	}
	recordAudit(toolGrants, "success", map[string]any{"count": len(usable)}, nil)
	return grantsView{
		Executor: executorView{UID: executorUID, Name: executorName},
		Grants:   usable,
		Invalid:  invalid,
	}, nil
}
