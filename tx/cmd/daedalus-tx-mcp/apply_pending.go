// apply_pending.go —— 第三档的落地:AI 出待办,人写批准记录,AI 再执行。
//
// 待办目录 1777(粘滞位,同 /tmp 语义)让 AI 以自己身份建待办;批准目录 0755
// root:root 让 AI 无论怎么折腾都批不了自己 —— 这道门的机制就是目录权限。
// 但"批准那一刻校验过一次"不等于"执行时还可信":目录与文件都可能在批准之后被
// 换掉,所以读侧独立再验一遍(非符号链接、属主 root、组/其他不可写),任一不满足
// 一律按批准无效处理,而不是当成"没有批准"去重新出待办。
//
// 批准绑定的是**具体 argv**:argv_sha256 用 NUL 连接后取 sha256(与签发/查看侧
// 同一算法),执行前重算并逐字比对 —— 参数变了就是新动作。
// 批准还有新鲜度:approved_at + approvalTTL > now 才算数,过期即作废 —— 批准是
// "这一小段时间内准你做这一件事",不是长期通行证。
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	// defaultPendingDir 是待办的生产位置:tmpfs ⇒ 待办不跨重启存活。
	defaultPendingDir = "/run/daedalus/pending"
	// defaultApprovalsDir 是批准记录的生产位置:只有 root 能写。
	defaultApprovalsDir = "/run/daedalus/approvals"
	// envPendingDir / envApprovalsDir 覆盖目录(测试隔离用);空值视为未设置。
	envPendingDir   = "DAEDALUS_PENDING_DIR"
	envApprovalsDir = "DAEDALUS_APPROVALS_DIR"
	// envApprovalTTL 覆盖批准新鲜度窗口(测试与运维调参用);空值视为未设置。
	envApprovalTTL = "DAEDALUS_APPROVAL_TTL"
	// maxApprovalFileBytes 给批准记录设上限:目录虽由 root 写,读侧不该按文件
	// 自称的大小整份读入。
	maxApprovalFileBytes = 64 << 10
)

// approvalTTL 是批准记录的新鲜度窗口:人批准之后必须在窗口内用掉,超时即失效。
//
// 与 pending TTL 同源,改一处必改另一处 —— 两者的有效期分开裁剪,就会出现
// "待办还在、批准已死"或反过来的时间窗,人批过的事与机器放行的事对不上。
//
// 窗口内允许同一意图重复执行:单次性在"批准目录只有 root 能写、但执行方是
// 调用用户"的前提下无法强制。真正的边界是作用域 + TTL + 签发者上限。
const approvalTTL = pendingTTL

// approvalDirOwnerUID 是批准目录要求的属主 uid:生产恒为 root(0)。
// 只在测试里被替换成调用者自己 —— 非 root 的测试进程建不出 root 拥有的目录,
// 而"批准记录可信 ⇒ 执行"这条路径必须能在测试里跑到。
var approvalDirOwnerUID = uint32(0)

// pendingDoc 是待办文件的线上形状(与 daedalus-tx pending list/show 同一契约)。
type pendingDoc struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Name         string   `json:"name"`
	DesiredState string   `json:"desired_state"`
	Argv         []string `json:"argv"`
	Scope        string   `json:"scope"`
	Reason       string   `json:"reason"`
	CreatedAt    string   `json:"created_at"`
	ExpiresAt    string   `json:"expires_at"`
}

// approvalDoc 是批准记录的线上形状(由 root 侧的 approve 写入)。
// 字段名与 core 的 daedalus-tx approve 逐字对齐:那是跨仓契约,改字段名
// 等于让已批准的记录全部读不出来。
type approvalDoc struct {
	ID         string `json:"id"`
	ArgvSHA256 string `json:"argv_sha256"`
	ApprovedBy string `json:"approved_by"`
	ApprovedAt string `json:"approved_at"`
}

// approvalStatus 把"读批准记录"的五种结论分开:没有、可信、不可信、指纹不符、
// 已过期。后三者都必须拒绝执行,但给客户端的理由不同。
type approvalStatus int

const (
	approvalAbsent approvalStatus = iota
	approvalTrusted
	approvalUntrusted
	approvalMismatched
	approvalStale
)

func pendingDir() string {
	if v := os.Getenv(envPendingDir); v != "" {
		return v
	}
	return defaultPendingDir
}

func approvalsDir() string {
	if v := os.Getenv(envApprovalsDir); v != "" {
		return v
	}
	return defaultApprovalsDir
}

// pendingIDFor 由意图(kind + 单元名 + 期望状态 + 作用域)派生一个确定性 id。
// 确定性是这套机制能闭合的原因:AI 第二次对同一意图调用时不需要客户端记住上次的
// id,就能找到人批准的那一条;改动任何参数都会得到新 id,也就没有可用的批准。
func pendingIDFor(kind, unit, desiredState, scope string) string {
	intent := strings.Join([]string{kind, unit, desiredState, scope}, "\x00")
	sum := sha256.Sum256([]byte(intent))
	return "p-" + hex.EncodeToString(sum[:8])
}

// argvSHA256 是"被批准的是哪条 argv"的规范指纹:逐元素用 NUL 连接后取 sha256。
// 分隔符必须是不可能出现在 argv 里的字节,否则 ["a b"] 与 ["a","b"] 会撞成一个。
func argvSHA256(argv []string) string {
	sum := sha256.Sum256([]byte(strings.Join(argv, "\x00")))
	return hex.EncodeToString(sum[:])
}

// writePending 原子写一份待办(临时文件 → fsync → rename,权限 0644)。
// 目录缺失时按生产语义补建(1777 粘滞):生产由 systemd-tmpfiles 建,缺失说明
// 部署不完整,但仍然要能把待办出出来,否则第三档等于完全不可用。
func writePending(doc pendingDoc) error {
	dir := pendingDir()
	// 只在目录不存在时补建并设权限:生产里目录由 systemd-tmpfiles 以 root 建好,
	// 每次写都去 chmod 会因"不是属主"失败,反而让第三档永远出不了待办。
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return fmt.Errorf("创建待办目录 %s 失败: %v", dir, err)
		}
		// MkdirAll 的 mode 会被 umask 削减;显式 chmod 保证同机其他用户也能看到待办。
		if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil {
			return fmt.Errorf("设置待办目录 %s 权限失败: %v", dir, err)
		}
	} else if err != nil {
		return fmt.Errorf("读取待办目录 %s 失败: %v", dir, err)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("序列化待办失败: %v", err)
	}
	tmp, err := os.CreateTemp(dir, ".pending-*.tmp")
	if err != nil {
		return fmt.Errorf("在 %s 建临时文件失败: %v", dir, err)
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("写待办失败: %v", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("设置待办权限失败: %v", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("flush 待办失败: %v", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭待办临时文件失败: %v", err)
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, doc.ID+".json")); err != nil {
		return fmt.Errorf("落位待办失败: %v", err)
	}
	renamed = true
	return nil
}

// loadApproval 读取并校验批准记录。目录/文件不可信、指纹不符与已过期分开报告:
// 前者是"这里被人动过手",后者是"人批的不是这条命令",最后一个是"人批得太早"。
func loadApproval(id string, argv []string, now time.Time) (approvalStatus, approvalDoc, error) {
	dir := approvalsDir()
	dirInfo, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return approvalAbsent, approvalDoc{}, nil
	}
	if err != nil {
		return approvalUntrusted, approvalDoc{}, fmt.Errorf("读取批准目录 %s 失败: %v", dir, err)
	}
	if err := checkApprovalsDirTrust(dir, dirInfo); err != nil {
		return approvalUntrusted, approvalDoc{}, err
	}

	path := filepath.Join(dir, id+".json")
	fileInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return approvalAbsent, approvalDoc{}, nil
	}
	if err != nil {
		return approvalUntrusted, approvalDoc{}, fmt.Errorf("读取批准记录 %s 失败: %v", path, err)
	}
	// 记录本身也不能是符号链接:文件的属主与内容都可能来自批准目录之外。
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		return approvalUntrusted, approvalDoc{}, fmt.Errorf("批准记录 %s 是符号链接,拒绝执行", path)
	}
	if !fileInfo.Mode().IsRegular() {
		return approvalUntrusted, approvalDoc{}, fmt.Errorf("批准路径 %s 不是普通文件", path)
	}

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return approvalUntrusted, approvalDoc{}, fmt.Errorf("打开批准记录 %s 失败: %v", path, err)
	}
	defer f.Close()
	data, err := readCappedReader(f, maxApprovalFileBytes)
	if err != nil {
		return approvalUntrusted, approvalDoc{}, fmt.Errorf("读批准记录 %s 失败: %v", path, err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc approvalDoc
	if err := dec.Decode(&doc); err != nil {
		return approvalUntrusted, approvalDoc{}, fmt.Errorf("批准记录 %s 无法解析: %v", path, err)
	}
	// 残余内容不能用 dec.More() 判:它对紧跟的 ] / } 会返回 false。
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return approvalUntrusted, approvalDoc{}, fmt.Errorf("批准记录 %s 在 JSON 之后有多余内容", path)
	}
	if doc.ID != id || doc.ApprovedBy == "" || doc.ApprovedAt == "" || doc.ArgvSHA256 == "" {
		return approvalUntrusted, approvalDoc{}, fmt.Errorf("批准记录 %s 字段不全或 id 不符", path)
	}
	if doc.ArgvSHA256 != argvSHA256(argv) {
		return approvalMismatched, approvalDoc{}, nil
	}
	// 新鲜度:批准不是长期通行证。人在 2am 批的"这一次",不能留到明天当
	// 无限次重放的凭据 —— 窗口过了就作废,重新申请、重新批。
	approvedAt, err := time.Parse(time.RFC3339, doc.ApprovedAt)
	if err != nil {
		return approvalUntrusted, approvalDoc{}, fmt.Errorf("批准记录 %s 的 approved_at 无法解析: %v", path, err)
	}
	ttl, err := approvalTTLValue()
	if err != nil {
		return approvalStale, approvalDoc{}, fmt.Errorf("批准新鲜度窗口不可用: %v", err)
	}
	if !approvedAt.Add(ttl).After(now) {
		return approvalStale, approvalDoc{}, fmt.Errorf(
			"批准记录 %s 已过新鲜度窗口(批准于 %s,窗口 %s)", path, doc.ApprovedAt, ttl)
	}
	return approvalTrusted, doc, nil
}

// approvalTTLValue 取批准新鲜度窗口:env 覆盖优先,值必须是 Go duration 字符串。
// 解析失败或非正数一律当配置不可用 —— fail-closed,不让一个写坏的环境变量
// 把窗口悄悄放大成"永久有效"。
func approvalTTLValue() (time.Duration, error) {
	v := os.Getenv(envApprovalTTL)
	if v == "" {
		return approvalTTL, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q 不是合法的 duration: %v", envApprovalTTL, v, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s=%q 必须是正时长", envApprovalTTL, v)
	}
	return d, nil
}

// checkApprovalsDirTrust 是批准目录的读侧判定:必须是真实目录(非符号链接)、
// 属主 root、组/其他不可写。任一条不成立,"只有 root 能写"就只是口号。
func checkApprovalsDirTrust(path string, fi os.FileInfo) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("批准路径 %s 是符号链接,拒绝执行", path)
	}
	if !fi.IsDir() {
		return fmt.Errorf("批准路径 %s 不是目录", path)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("无法判定批准目录 %s 的属主,拒绝执行", path)
	}
	if stat.Uid != approvalDirOwnerUID {
		return fmt.Errorf("批准目录 %s 的属主 uid=%d,期望 %d(生产为 root),拒绝执行", path, stat.Uid, approvalDirOwnerUID)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("批准目录 %s 对其他用户可写(mode=%o),拒绝执行", path, perm)
	}
	return nil
}

// readCappedReader 读文件但拒绝超过上限的内容:目录属主可写的文件不该让读方
// 按写入方指定的大小分配内存。
func readCappedReader(f io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("文件超过 %d 字节上限", limit)
	}
	return data, nil
}
