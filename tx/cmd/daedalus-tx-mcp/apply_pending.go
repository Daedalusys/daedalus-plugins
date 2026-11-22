// apply_pending.go —— 第三档的落地:AI 出待办,人写批准记录,AI 再执行。
//
// 待办按人分目录:<根>/<uid>(0700,属主是本人)—— 别人的待办在文件系统层就读不到,
// 别人也抢建不了同名文件卡住本人的落位。根目录 1777(粘滞位,同 /tmp 语义)由
// systemd-tmpfiles 建;用户子目录由本插件建,用之前必须核对属主是自己的,否则
// fail-closed 而不是接管(见 ensureUserDir)。
//
// 批准目录仍是 0755 root:root,让 AI 无论怎么折腾都批不了自己 —— 这道门的机制
// 就是目录权限。但"批准那一刻校验过一次"不等于"执行时还可信":目录与文件都可能
// 在批准之后被换掉,所以读侧独立再验一遍(非符号链接、属主 root、组/其他不可写),
// 任一不满足一律按批准无效处理,而不是当成"没有批准"去重新出待办。
//
// 批准绑定的是**具体 argv**(argv_sha256:逐元素 NUL 连接后取 sha256,与签发/查看侧
// 同一算法),执行前重算并逐字比对 —— 参数变了就是新动作。指纹算法与待办的线上
// 形状都在 SDK 的 pending 包里,本文件只消费,不再持有副本。
//
// 批准还有新鲜度:approved_at + approvalTTL > now 才算数,过期即作废 —— 批准是
// "这一小段时间内准你做这一件事",不是长期通行证。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Daedalusys/daedalus-sdk/pending"
)

const (
	// defaultPendingDir 是待办的生产根目录:tmpfs ⇒ 待办不跨重启存活。
	// 每个执行者用其中的 <根>/<uid> 子目录,见 pendingDirFor。
	defaultPendingDir = "/run/daedalus/pending"
	// defaultApprovalsDir 是批准记录的生产位置:只有 root 能写。
	defaultApprovalsDir = "/run/daedalus/approvals"
	// defaultConsumedDir 是消费标记的父目录:1777 由 systemd-tmpfiles 建,
	// 每个执行者在里面建自己的 <uid> 子目录。
	defaultConsumedDir = "/run/daedalus/consumed"
	// envPendingDir / envApprovalsDir / envConsumedDir 覆盖目录(测试隔离用);
	// 空值视为未设置。envPendingDir 与 envConsumedDir 指的是**根目录**,
	// 不是某个用户的子目录。
	envPendingDir   = "DAEDALUS_PENDING_DIR"
	envApprovalsDir = "DAEDALUS_APPROVALS_DIR"
	envConsumedDir  = "DAEDALUS_CONSUMED_DIR"
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
// 单次性由消费标记兜住(claimApproval),窗口本身只管"批得太早"作废。
const approvalTTL = pendingTTL

// approvalDirOwnerUID 是批准目录要求的属主 uid:生产恒为 root(0)。
// 只在测试里被替换成调用者自己 —— 非 root 的测试进程建不出 root 拥有的目录,
// 而"批准记录可信 ⇒ 执行"这条路径必须能在测试里跑到。
var approvalDirOwnerUID = uint32(0)

// approvalStatus 把"读批准记录"的结论分开:没有、可信、不可信、指纹不符、
// 已过期、批给了别人。后四者都必须拒绝执行,但给客户端的理由不同。
type approvalStatus int

const (
	approvalAbsent approvalStatus = iota
	approvalTrusted
	approvalUntrusted
	approvalMismatched
	approvalStale
	approvalForOtherUser
)

// errApprovalConsumed 是"这份批准已经被占过"的哨兵:重放与"占不住"必须能分开,
// 前者是正常拒绝,后者是环境坏了。
var errApprovalConsumed = errors.New("这份批准已经用过了")

// pendingRoot 是待办根目录:用户子目录由 pendingDirFor 拼出。
func pendingRoot() string {
	if v := os.Getenv(envPendingDir); v != "" {
		return v
	}
	return defaultPendingDir
}

// pendingDirFor 是某个执行者的待办目录。
// 目录里是本人的 argv,不该让同机其他用户读到,所以按人分目录(0700)。
func pendingDirFor(uid uint32) string {
	return filepath.Join(pendingRoot(), strconv.FormatUint(uint64(uid), 10))
}

// approvalsDir 是共享的批准目录:只有 root 能写,所以不按人分。
func approvalsDir() string {
	if v := os.Getenv(envApprovalsDir); v != "" {
		return v
	}
	return defaultApprovalsDir
}

// consumedRoot 是消费标记的父目录:子目录由 consumedDirFor 拼出。
func consumedRoot() string {
	if v := os.Getenv(envConsumedDir); v != "" {
		return v
	}
	return defaultConsumedDir
}

// consumedDirFor 是某个执行者的消费标记目录。
// 标记只拦得住意外重放(标记归自己所有,自己就能截断),所以它和待办一样
// 按人分目录:别人的标记不该影响本人能不能用掉自己的批准。
func consumedDirFor(uid uint32) string {
	return filepath.Join(consumedRoot(), strconv.FormatUint(uint64(uid), 10))
}

// claimApproval 占住一份批准:O_EXCL 建标记,天然原子,第二次占必然失败。
//
// 标记归执行者自己所有,可以自己截断 ⇒ 挡得住意外重放(循环、重试、重复提交),
// 挡不住恶意重放。这与条子的 max_uses 同性质:速率限制,不是安全边界。
func claimApproval(id string) error {
	if err := pending.ValidateID(id); err != nil {
		return fmt.Errorf("拒绝为 %q 建消费标记: %v", id, err)
	}
	dir := consumedDirFor(executorUID)
	if err := ensureUserDir(dir, executorUID); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w(待办 %s 的批准)", errApprovalConsumed, id)
		}
		return fmt.Errorf("占住批准 %s 失败: %v", id, err)
	}
	return f.Close()
}

// ensureUserDir 确认 <根>/<uid> 这个目录归本人,不存在就按 0700 建出来。
//
// 属主不是本人时只能拒绝:别人拥有的目录,别人随时能往里塞文件、删文件,
// 在这个目录上谈"这份待办是本人出的"就不成立了。接管(改属主)或 chmod
// 都不能解决这个问题 —— 那把目录的语义交给了攻击者,只会在下一次被换回去。
// 处置只能由管理员删掉目录后重来,所以错误串给出可照抄的命令。
func ensureUserDir(path string, uid uint32) error {
	fi, err := os.Lstat(path)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		// 并发下后到者会撞 EEXIST:那不是失败,目录已经在了,照常往下核对属主。
		if mkErr := os.Mkdir(path, 0o700); mkErr == nil {
			created = true
		} else if !errors.Is(mkErr, os.ErrExist) {
			return fmt.Errorf("创建目录 %s 失败: %v", path, mkErr)
		}
		if fi, err = os.Lstat(path); err != nil {
			return fmt.Errorf("读取目录 %s 失败: %v", path, err)
		}
	} else if err != nil {
		return fmt.Errorf("读取目录 %s 失败: %v", path, err)
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("目录 %s 是符号链接,拒绝使用;请管理员执行 sudo rm -rf %s 后重试", path, path)
	}
	if !fi.IsDir() {
		return fmt.Errorf("路径 %s 不是目录,拒绝使用;请管理员执行 sudo rm -rf %s 后重试", path, path)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("无法判定目录 %s 的属主,拒绝使用", path)
	}
	if stat.Uid != uid {
		return fmt.Errorf("目录 %s 属主不是 uid=%d(别人随时能往里塞文件),拒绝使用;请管理员执行 sudo rm -rf %s 后重试",
			path, uid, path)
	}
	// 新建目录要复核模式:umask 会削减 Mkdir 的 mode,一个 0755 的"私人"目录
	// 等于把待办清单公开给同机所有用户。
	if created {
		if perm := fi.Mode().Perm(); perm != 0o700 {
			return fmt.Errorf("新建目录 %s 的模式是 %o,期望 0700(umask 过宽);请管理员执行 sudo rm -rf %s 后重试",
				path, perm, path)
		}
	}
	return nil
}

// writePending 原子写一份待办(临时文件 → fsync → rename,权限 0644)。
//
// 落点是执行者自己的目录;根目录由 systemd-tmpfiles 建,缺它说明部署不完整,
// 本函数不去补建 —— 补建根目录会掩盖部署缺口,而用户子目录才是需要核对属主的那层。
func writePending(doc pending.Pending) error {
	dir := pendingDirFor(executorUID)
	if err := ensureUserDir(dir, executorUID); err != nil {
		return err
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
func loadApproval(id string, argv []string, now time.Time) (approvalStatus, pending.Approval, error) {
	dir := approvalsDir()
	dirInfo, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return approvalAbsent, pending.Approval{}, nil
	}
	if err != nil {
		return approvalUntrusted, pending.Approval{}, fmt.Errorf("读取批准目录 %s 失败: %v", dir, err)
	}
	if err := checkApprovalsDirTrust(dir, dirInfo); err != nil {
		return approvalUntrusted, pending.Approval{}, err
	}

	path := filepath.Join(dir, id+".json")
	fileInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return approvalAbsent, pending.Approval{}, nil
	}
	if err != nil {
		return approvalUntrusted, pending.Approval{}, fmt.Errorf("读取批准记录 %s 失败: %v", path, err)
	}
	// 记录本身也不能是符号链接:文件的属主与内容都可能来自批准目录之外。
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		return approvalUntrusted, pending.Approval{}, fmt.Errorf("批准记录 %s 是符号链接,拒绝执行", path)
	}
	if !fileInfo.Mode().IsRegular() {
		return approvalUntrusted, pending.Approval{}, fmt.Errorf("批准路径 %s 不是普通文件", path)
	}

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return approvalUntrusted, pending.Approval{}, fmt.Errorf("打开批准记录 %s 失败: %v", path, err)
	}
	defer f.Close()
	data, err := readCappedReader(f, maxApprovalFileBytes)
	if err != nil {
		return approvalUntrusted, pending.Approval{}, fmt.Errorf("读批准记录 %s 失败: %v", path, err)
	}

	// 严格解析在 SDK 里:未知键、尾串、缺字段、requested_by_uid 缺失都算坏文件。
	doc, err := pending.ParseApproval(data)
	if err != nil {
		return approvalUntrusted, pending.Approval{}, fmt.Errorf("批准记录 %s 无法解析: %v", path, err)
	}
	// 请求者核对:这份批准批的必须是本人的请求。id 里带执行者只是"碰巧落不到
	// 别人头上",这里才是显式判定 —— 少了它,别人在同一个 id 上放的待办被批之后,
	// 本人指纹对得上就执行了,批准成了一条无主的 argv。
	// uid 0 是 root 本人,不是"未指定";解析期已把缺失当坏文件拒掉。
	if doc.RequestedByUID == nil {
		return approvalForOtherUser, pending.Approval{}, fmt.Errorf(
			"批准记录 %s 没有记录请求者(缺失不等于 root),拒绝执行", path)
	}
	if *doc.RequestedByUID != executorUID {
		return approvalForOtherUser, pending.Approval{}, fmt.Errorf(
			"批准记录 %s 批的是 %q(uid=%d)的请求,不是你的(uid=%d),拒绝执行",
			path, doc.RequestedBy, *doc.RequestedByUID, executorUID)
	}
	if doc.ID != id {
		return approvalUntrusted, pending.Approval{}, fmt.Errorf("批准记录 %s 的内容 id=%q 与文件名不符", path, doc.ID)
	}
	if doc.ArgvSHA256 != pending.ArgvSHA256(argv) {
		return approvalMismatched, pending.Approval{}, nil
	}
	// 新鲜度:批准不是长期通行证。人在 2am 批的"这一次",不能留到明天当
	// 无限次重放的凭据 —— 窗口过了就作废,重新申请、重新批。
	ttl, err := approvalTTLValue()
	if err != nil {
		return approvalStale, pending.Approval{}, fmt.Errorf("批准新鲜度窗口不可用: %v", err)
	}
	if !doc.ApprovedAt.Add(ttl).After(now) {
		return approvalStale, pending.Approval{}, fmt.Errorf(
			"批准记录 %s 已过新鲜度窗口(批准于 %s,窗口 %s)",
			path, doc.ApprovedAt.UTC().Format(time.RFC3339), ttl)
	}
	return approvalTrusted, *doc, nil
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
