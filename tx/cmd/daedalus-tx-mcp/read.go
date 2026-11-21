// read.go —— 只读面:tx_status / tx_list / tx_pending。
//
// 三者都只观测既有事实:tx_status 经 core CLI 的 status 子命令读单条 journal,
// tx_list 直接枚举 journal 目录,tx_pending 直接枚举待办目录。唯一的写是审计链
// (每次调用留证据);待办目录绝不写入 —— AI 能读到自己出过的待办,但"批准"
// 只能由人经 root 侧的命令做。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Daedalusys/daedalus-sdk/dirs"
)

const (
	// 工具名与 manifest.tools 逐字一致,同时是审计链里的 tool 字段。
	toolStatus  = "tx_status"
	toolList    = "tx_list"
	toolPending = "tx_pending"

	// codeInvalidTxID:tx-id 未过形状门,触碰 CLI/文件系统之前就拒绝。
	codeInvalidTxID = "invalid_tx_id"
	// codePendingUnreadable:待办目录或文件读不了 / 形状不全是异常信号。
	codePendingUnreadable = "pending_unreadable"
	// codeInvalidLimit:limit 为负数没有语义,不猜意图。
	codeInvalidLimit = "invalid_limit"

	// maxJournalFileBytes 给单份 journal 设上限:读侧不按写入方自称的大小整份读入。
	maxJournalFileBytes = 1 << 20
	// maxPendingFileBytes 与批准记录的读侧上限同量级。
	maxPendingFileBytes = 64 << 10
)

// txStatusSet 是 core 事务状态全集。journal 里的 status 表外即视为损坏:
// 展示一个客户端不认识的 state 只会让上游误判。
var txStatusSet = map[string]bool{
	"proposed":    true,
	"applying":    true,
	"applied":     true,
	"rolled_back": true,
	"failed":      true,
}

type statusIn struct {
	TxID string `json:"tx_id"`
}

// statusView 是 tx_status 的应答:只透传核心三键,不把整份 journal 原样抛给客户端。
type statusView struct {
	TxID  string            `json:"tx_id"`
	State string            `json:"state"`
	Steps []json.RawMessage `json:"steps"`
}

type listIn struct {
	// Limit 为 0 表示不截断;负数无意义,直接拒绝。
	Limit int `json:"limit"`
}

type listItem struct {
	TxID      string    `json:"tx_id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
}

type listView struct {
	Items []listItem `json:"items"`
}

type pendingItem struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Name         string   `json:"name"`
	DesiredState string   `json:"desired_state"`
	Scope        string   `json:"scope"`
	Argv         []string `json:"argv"`
	// ArgvSHA256 是读侧现算的指纹:待办文件里没有这个键,人抄给 approve 的
	// --expect-sha256 就是这里给出的值。
	ArgvSHA256 string `json:"argv_sha256"`
	Reason     string `json:"reason"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
}

type pendingView struct {
	Items []pendingItem `json:"items"`
}

// journalDoc 是 core CLI status 输出的核心字段(Transaction 的超集)。
type journalDoc struct {
	ID        string            `json:"id"`
	Status    string            `json:"status"`
	CreatedAt time.Time         `json:"created_at"`
	Steps     []json.RawMessage `json:"steps"`
}

// readJournal 经 core CLI 读单条 journal。CLI 的 stdout 也按内容 id 复核:
// 一个不合格的文档被当成目标事务,后续回滚就会作用到别的东西上。
func readJournal(txID string) (journalDoc, *structuredError) {
	stdout, stderrText, rc, err := runTx("status", txID)
	if err != nil {
		return journalDoc{}, &structuredError{Error: codeTxFailed, Detail: shortErrText(err)}
	}
	if rc != 0 {
		return journalDoc{}, &structuredError{
			Error:  codeTxFailed,
			Detail: shortErrText(cliFailure("status", rc, stdout, stderrText)),
		}
	}
	var doc journalDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		return journalDoc{}, &structuredError{Error: codeTxFailed, Detail: "daedalus-tx status 输出不是 JSON: " + shortErrText(err)}
	}
	if doc.ID != txID {
		return journalDoc{}, &structuredError{
			Error:  codeTxFailed,
			Detail: fmt.Sprintf("journal 内容 id=%q 与请求 id=%q 不一致", doc.ID, txID),
		}
	}
	if !txStatusSet[doc.Status] {
		return journalDoc{}, &structuredError{
			Error:  codeTxFailed,
			Detail: fmt.Sprintf("journal 状态 %q 不在状态全集内", doc.Status),
		}
	}
	if doc.Steps == nil {
		doc.Steps = []json.RawMessage{}
	}
	return doc, nil
}

// txStatus 读一条事务并只回核心字段。所有失败都在触碰 CLI 之前尽量拦掉。
func txStatus(in statusIn) (statusView, *structuredError) {
	args := map[string]any{"tx_id": in.TxID}
	if !txIDPattern.MatchString(in.TxID) {
		args["error"] = codeInvalidTxID
		recordAudit(toolStatus, "denied", args, nil)
		return statusView{}, &structuredError{
			Error:  codeInvalidTxID,
			Detail: fmt.Sprintf("tx_id 必须是 16 位小写十六进制: %q", in.TxID),
		}
	}
	doc, serr := readJournal(in.TxID)
	if serr != nil {
		args["error"] = serr.Error
		recordAudit(toolStatus, "error", args, nil)
		return statusView{}, serr
	}
	args["state"] = doc.Status
	recordAudit(toolStatus, "success", args, nil)
	return statusView{TxID: doc.ID, State: doc.Status, Steps: doc.Steps}, nil
}

// txList 直接枚举 journal 目录:文件名必须同时是合法 tx-id,内容 id 必须与文件名
// 一致,形状坏掉就整批报错 —— 静默跳过一条等于向客户端隐瞒一次事务。
func txList(in listIn) (listView, *structuredError) {
	args := map[string]any{"limit": in.Limit}
	if in.Limit < 0 {
		args["error"] = codeInvalidLimit
		recordAudit(toolList, "denied", args, nil)
		return listView{}, &structuredError{Error: codeInvalidLimit, Detail: "limit 不能为负数"}
	}
	root, err := dirs.TxRoot()
	if err != nil {
		args["error"] = codeTxFailed
		recordAudit(toolList, "error", args, nil)
		return listView{}, &structuredError{Error: codeTxFailed, Detail: shortErrText(err)}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		args["error"] = codeTxFailed
		recordAudit(toolList, "error", args, nil)
		return listView{}, &structuredError{Error: codeTxFailed, Detail: shortErrText(err)}
	}

	items := make([]listItem, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || entry.IsDir() {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if !txIDPattern.MatchString(id) {
			// 杂散文件不是 journal,不参与枚举也不算错(与 core 的 List 同纪律)。
			continue
		}
		item, err := loadJournalItem(filepath.Join(root, name), id)
		if err != nil {
			args["error"] = codeTxFailed
			recordAudit(toolList, "error", args, nil)
			return listView{}, &structuredError{Error: codeTxFailed, Detail: shortErrText(err)}
		}
		items = append(items, item)
	}

	// 最近 N 条:时间倒序;同一时刻按 id 倒序,保证输出全序可复现。
	sort.Slice(items, func(i, j int) bool {
		if !items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].TxID > items[j].TxID
	})
	if in.Limit > 0 && len(items) > in.Limit {
		items = items[:in.Limit]
	}
	args["count"] = len(items)
	recordAudit(toolList, "success", args, nil)
	return listView{Items: items}, nil
}

// loadJournalItem 读一份 journal 的展示字段。读侧独立复核文件名/内容 id 一致性,
// 不把 core 的校验当成本地保证。
func loadJournalItem(path, id string) (listItem, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return listItem{}, fmt.Errorf("读取 journal %s 失败: %v", path, err)
	}
	// 符号链接可以把"读 journal"变成"读任意文件",目录又对写入方开放,必须拒。
	if fi.Mode()&os.ModeSymlink != 0 {
		return listItem{}, fmt.Errorf("journal %s 是符号链接,拒绝", path)
	}
	if !fi.Mode().IsRegular() {
		return listItem{}, fmt.Errorf("journal %s 不是普通文件", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return listItem{}, fmt.Errorf("打开 journal %s 失败: %v", path, err)
	}
	defer f.Close()
	data, err := readCappedReader(f, maxJournalFileBytes)
	if err != nil {
		return listItem{}, fmt.Errorf("读 journal %s 失败: %v", path, err)
	}
	var doc struct {
		ID        string    `json:"id"`
		Status    string    `json:"status"`
		CreatedAt time.Time `json:"created_at"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return listItem{}, fmt.Errorf("journal %s 无法解析: %v", path, err)
	}
	if doc.ID != id {
		return listItem{}, fmt.Errorf("journal %s 内容 id=%q 与文件名不一致", path, doc.ID)
	}
	if !txStatusSet[doc.Status] {
		return listItem{}, fmt.Errorf("journal %s 状态 %q 不在状态全集内", path, doc.Status)
	}
	if doc.CreatedAt.IsZero() {
		return listItem{}, fmt.Errorf("journal %s 缺 created_at", path)
	}
	return listItem{TxID: doc.ID, State: doc.Status, CreatedAt: doc.CreatedAt}, nil
}

// txPending 只列待办 *.json,并按线上契约原样透出字段(argv 是指纹的来源,
// 空 argv 的待办无法被人核对,按损坏处理)。全程零写入。
func txPending() (pendingView, *structuredError) {
	dir := pendingDir()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		// 全新机器还没出过待办:空列表,不是错误。
		recordAudit(toolPending, "success", map[string]any{"count": 0}, nil)
		return pendingView{Items: []pendingItem{}}, nil
	}
	if err != nil {
		recordAudit(toolPending, "error", map[string]any{"error": codePendingUnreadable}, nil)
		return pendingView{}, &structuredError{Error: codePendingUnreadable, Detail: shortErrText(err)}
	}

	type entryWithTime struct {
		item    pendingItem
		created time.Time
	}
	entriesWithTimes := make([]entryWithTime, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		item, createdAt, err := loadPendingItem(path, strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			recordAudit(toolPending, "error", map[string]any{"error": codePendingUnreadable}, nil)
			return pendingView{}, &structuredError{Error: codePendingUnreadable, Detail: shortErrText(err)}
		}
		entriesWithTimes = append(entriesWithTimes, entryWithTime{item: item, created: createdAt})
	}

	// 最近的待办排前面;同刻按 id 升序,输出全序可复现。
	sort.Slice(entriesWithTimes, func(i, j int) bool {
		if !entriesWithTimes[i].created.Equal(entriesWithTimes[j].created) {
			return entriesWithTimes[i].created.After(entriesWithTimes[j].created)
		}
		return entriesWithTimes[i].item.ID < entriesWithTimes[j].item.ID
	})
	items := make([]pendingItem, 0, len(entriesWithTimes))
	for _, e := range entriesWithTimes {
		items = append(items, e.item)
	}
	recordAudit(toolPending, "success", map[string]any{"count": len(items)}, nil)
	return pendingView{Items: items}, nil
}

// loadPendingItem 读一份待办并复核形状。文件名即 id:内容与文件名对不上时
// 无法判断人批准的是哪一条,只能按损坏处理(fail-closed)。
func loadPendingItem(path, id string) (pendingItem, time.Time, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return pendingItem{}, time.Time{}, fmt.Errorf("读取待办 %s 失败: %v", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return pendingItem{}, time.Time{}, fmt.Errorf("待办 %s 是符号链接,拒绝", path)
	}
	if !fi.Mode().IsRegular() {
		return pendingItem{}, time.Time{}, fmt.Errorf("待办 %s 不是普通文件", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return pendingItem{}, time.Time{}, fmt.Errorf("打开待办 %s 失败: %v", path, err)
	}
	defer f.Close()
	data, err := readCappedReader(f, maxPendingFileBytes)
	if err != nil {
		return pendingItem{}, time.Time{}, fmt.Errorf("读待办 %s 失败: %v", path, err)
	}
	var doc pendingDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return pendingItem{}, time.Time{}, fmt.Errorf("待办 %s 无法解析: %v", path, err)
	}
	if doc.ID != id {
		return pendingItem{}, time.Time{}, fmt.Errorf("待办 %s 内容 id=%q 与文件名不一致", path, doc.ID)
	}
	if doc.Scope == "" || len(doc.Argv) == 0 {
		return pendingItem{}, time.Time{}, fmt.Errorf("待办 %s 缺 scope 或 argv,人无法据此批准", path)
	}
	createdAt, err := time.Parse(time.RFC3339, doc.CreatedAt)
	if err != nil {
		return pendingItem{}, time.Time{}, fmt.Errorf("待办 %s 的 created_at 非法: %v", path, err)
	}
	if doc.ExpiresAt == "" {
		return pendingItem{}, time.Time{}, fmt.Errorf("待办 %s 缺 expires_at", path)
	}
	return pendingItem{
		ID:           doc.ID,
		Kind:         doc.Kind,
		Name:         doc.Name,
		DesiredState: doc.DesiredState,
		Scope:        doc.Scope,
		Argv:         doc.Argv,
		ArgvSHA256:   argvSHA256(doc.Argv),
		Reason:       doc.Reason,
		CreatedAt:    doc.CreatedAt,
		ExpiresAt:    doc.ExpiresAt,
	}, createdAt, nil
}
