// apply_grant.go —— 第二档的条子消费:读文件、按文件属主判定签发者、记账后放行。
//
// 校验的唯一权威在消费侧:签发命令签完那一刻的结论不算数,这里按"文件属主 +
// 签发者名单 + 上限 + 覆盖关系 + 用量"重新判一遍。JSON 里的 issued_by 只是线索。
//
// 单次性:SDK 只给"读计数"与"追加计数"两个原语,没有"检查+占用"的原子操作,
// 所以"折叠 → 判定 → 记账"三步由本进程的同一把互斥锁串起来。跨进程并发不支持:
// 同一台机器只应有一个 daedalus-tx-mcp 实例(多实例会让内存计数各自为政)。
package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
	"github.com/Daedalusys/daedalus-sdk/grant"
)

const (
	// defaultGrantsDir 是条子目录的生产位置(与签发命令同一常量口径)。
	defaultGrantsDir = "/run/daedalus/grants"
	// envGrantsDir 覆盖条子目录(测试隔离用);空值视为未设置。
	envGrantsDir = "DAEDALUS_GRANTS_DIR"
	// maxGrantFileBytes 给条子文件设上限:目录对签发者组可写,不设上限就等于
	// 让消费侧按写入方指定的大小整份读入。
	maxGrantFileBytes = 64 << 10
)

// errGrantExhausted 把"次数用完"与"记账失败"区分开:前者是正常拒绝,后者是故障。
var errGrantExhausted = errors.New("条子已用尽")

func grantsDir() string {
	if v := os.Getenv(envGrantsDir); v != "" {
		return v
	}
	return defaultGrantsDir
}

// grantPath 拼条子文件路径。id 来自客户端,触碰路径之前先过形状门,并复核解析后
// 仍在条子目录内 —— 一个 ".." 就能把"读条子"变成"读任意 JSON"。
func grantPath(dir, id string) (string, error) {
	if err := validateGrantID(id); err != nil {
		return "", err
	}
	path := filepath.Join(dir, id+".json")
	if filepath.Dir(path) != filepath.Clean(dir) {
		return "", fmt.Errorf("条子 id %q 非法(解析后逃出条子目录)", id)
	}
	return path, nil
}

// validateGrantID 与 SDK 的条子 id 门同款:不许路径分隔符/相对记号/控制字符。
func validateGrantID(id string) error {
	switch {
	case id == "":
		return fmt.Errorf("条子 id 为空")
	case len(id) > 128:
		return fmt.Errorf("条子 id 过长(最多 128 字节)")
	case id == "." || id == "..":
		return fmt.Errorf("条子 id 不得是相对路径记号")
	case strings.ContainsAny(id, "/\\\x00"):
		return fmt.Errorf("条子 id 不得含路径分隔符")
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("条子 id 不得含控制字符")
		}
	}
	return nil
}

// consumeGrant 完成一次条子消费:读 → Parse → Authorize → Covers → 未过期 → 记账。
// 返回 nil 表示"可以执行且用量已记上";返回拒绝表示一步都不许动。
func consumeGrant(cfg *autonomy.Config, grantID string, scope autonomy.Scope, now time.Time) *applyRejection {
	path, err := grantPath(grantsDir(), grantID)
	if err != nil {
		return &applyRejection{Error: codeGrantInvalid, Reason: "条子 id 非法", Detail: err.Error()}
	}

	ownerUID, ownerName, data, err := readGrantFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// 撤销 = 删文件:这与"根本没传条子"必须给出不同理由。
		return &applyRejection{
			Error:  codeGrantRevoked,
			Reason: "条子不存在(可能已被撤销)",
			Detail: fmt.Sprintf("条子 %s 的文件不在条子目录里", grantID),
		}
	}
	if err != nil {
		return &applyRejection{Error: codeGrantInvalid, Reason: "条子文件不可读", Detail: shortErrText(err)}
	}

	g, err := grant.Parse(data)
	if err != nil {
		return &applyRejection{Error: codeGrantInvalid, Reason: "条子文件无法解析", Detail: shortErrText(err)}
	}
	// 文件名与内容 id 不一致:两份事实源对不上,不能挑一份信。
	if g.ID != grantID {
		return &applyRejection{
			Error:  codeGrantInvalid,
			Reason: "条子文件内容与 id 不一致",
			Detail: fmt.Sprintf("文件名 id=%q, 文件内 id=%q", grantID, g.ID),
		}
	}

	if err := grant.Authorize(cfg, g, ownerUID, ownerName, now); err != nil {
		return authorizeRejection(g, now, err)
	}
	if !g.Covers(scope) {
		return &applyRejection{
			Error:         codeGrantScopeMismatch,
			Reason:        "条子作用域不覆盖本次动作",
			RequiredScope: []string{scope.String()},
			Detail:        "条子签的是别的动作或别的对象;参数变了就是新动作,需要重新签发",
		}
	}
	// Authorize 已判过有效期;这里再显式判一次,免得将来改动 Authorize 的顺序时
	// 过期条子被静默放行。
	if g.Expired(now) {
		return &applyRejection{Error: codeGrantExpired, Reason: "条子已过期", Detail: "请重新签发"}
	}

	if err := grantUsage.consume(grantID, g.MaxUses, now); err != nil {
		if errors.Is(err, errGrantExhausted) {
			return &applyRejection{
				Error:  codeGrantExhausted,
				Reason: "条子已用尽",
				Detail: fmt.Sprintf("该条子已用满 %d 次;需要新条子", g.MaxUses),
			}
		}
		// 记不上就不执行:先做后记等于条子可以无限用。
		return &applyRejection{Error: codeGrantUsageFailed, Reason: "条子用量记账失败,拒绝执行", Detail: shortErrText(err)}
	}
	return nil
}

// authorizeRejection 把 Authorize 的失败翻译成可区分的理由。Authorize 没有哨兵
// 错误,所以这里按它自己的闸门顺序复判一次(全局上限 → 过期 → 签发者)。
func authorizeRejection(g *grant.Grant, now time.Time, cause error) *applyRejection {
	switch {
	case g.MaxUses > grant.GlobalMaxUses:
		return &applyRejection{Error: codeGrantInvalid, Reason: "条子次数超过全局上限", Detail: shortErrText(cause)}
	case g.ExpiresAt.Sub(now) > grant.GlobalMaxTTL:
		return &applyRejection{Error: codeGrantInvalid, Reason: "条子有效期超过全局上限", Detail: shortErrText(cause)}
	case g.Expired(now):
		return &applyRejection{Error: codeGrantExpired, Reason: "条子已过期", Detail: "请重新签发"}
	default:
		return &applyRejection{Error: codeGrantUnauthorized, Reason: "条子无效:签发者无权签这个范围/时长/次数", Detail: shortErrText(cause)}
	}
}

// readGrantFile 读条子文件并解析出权威签发身份(文件属主)。
// 用 Lstat + O_NOFOLLOW:条子目录对签发者组可写,一条符号链接就能把"属主"换成
// 链接目标的属主,签发者名单因此被绕过。
func readGrantFile(path string) (ownerUID uint32, ownerName string, data []byte, err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, "", nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return 0, "", nil, fmt.Errorf("条子文件 %s 是符号链接,拒绝", path)
	}
	if !fi.Mode().IsRegular() {
		return 0, "", nil, fmt.Errorf("条子路径 %s 不是普通文件", path)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, "", nil, fmt.Errorf("无法判定条子文件 %s 的属主", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, "", nil, err
	}
	defer f.Close()
	data, err = readCappedReader(f, maxGrantFileBytes)
	if err != nil {
		return 0, "", nil, err
	}
	return stat.Uid, lookupUserName(stat.Uid), data, nil
}

// lookupUserName 把 uid 翻成账号名(签发者名单按名字配置)。翻不出来返回空串:
// Authorize 会把空名字当成"不在名单内",即 fail-closed。
func lookupUserName(uid uint32) string {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil || u == nil {
		return ""
	}
	return u.Username
}

// usageLedger 是条子用量的进程内视图:首次消费时把 append-only 记账折叠成计数,
// 之后以内存计数判定。"判定 + 记账"在同一把锁内完成 —— 只靠 RecordUse 的 flock
// 挡不住两个请求同时读到旧计数。
type usageLedger struct {
	mu     sync.Mutex
	loaded bool
	path   string
	counts map[string]int
}

// grantUsage 是进程级账本。测试通过 newUsageLedger() 换一个空账本隔离用例。
var grantUsage = newUsageLedger()

func newUsageLedger() *usageLedger {
	return &usageLedger{counts: map[string]int{}}
}

// consume 在锁内完成"折叠 → 判定 → 记账 → 计数自增"。记账失败会让本次拒绝,
// 且内存计数不前进(下次仍会尝试记账,不会被一次失败永久消费掉)。
func (l *usageLedger) consume(grantID string, maxUses int, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.loadLocked(); err != nil {
		return err
	}
	if l.counts[grantID] >= maxUses {
		return errGrantExhausted
	}
	if err := grant.RecordUse(l.path, grantID, now); err != nil {
		return fmt.Errorf("写入用量记账失败: %w", err)
	}
	l.counts[grantID]++
	return nil
}

// load 把 append-only 记账折叠进内存:服务器启动时调用一次,之后以内存计数判定。
// 折叠失败不拒启(写通道还能处理第一档与第三档),但会让第二档 fail-closed:
// 计数不可信时宁可拒绝,也不能把"不知道用了几次"当成"一次都没用"。
func (l *usageLedger) load() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loadLocked()
}

// loadLocked 是折叠本体(调用方持锁):成功才置 loaded,失败留下次重试。
func (l *usageLedger) loadLocked() error {
	if l.loaded {
		return nil
	}
	path, err := grant.UsageLogPath()
	if err != nil {
		return fmt.Errorf("解析用量日志路径失败: %w", err)
	}
	counts, err := grant.UsedCounts(path)
	if err != nil {
		return fmt.Errorf("折叠用量记账失败: %w", err)
	}
	l.path = path
	l.counts = counts
	l.loaded = true
	return nil
}
