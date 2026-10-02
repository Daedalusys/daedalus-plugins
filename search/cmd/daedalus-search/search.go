// search.go 是 daedalus.search 的实现:Baloo 索引文件/内容只读搜索 +
// search_reindex L1 deferred 占位。
//
// Baloo 不提供 D-Bus 查询接口,真实查询走 baloosearch(链接 libKF6Baloo,
// 直读 Baloo sqlite 索引);故用两条独立路径:D-Bus(godbus 探测可用性门禁)
// 与 CLI(execHelper fork baloosearch,解析 stdout 后客户端侧二次过滤)。
// search_reindex 恒返回 Started=false + note,不调 daemon、不动 daedalus-tx。
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// searchTimeout 是单次 baloosearch 调用超时。Baloo 查询通常毫秒级,缺索引时
// 也只走 sqlite 扫描,30s 充裕。
const searchTimeout = 30 * time.Second

// defaultBalooSearch 是找不到 baloosearch 时的兜底路径。
const defaultBalooSearch = "/usr/bin/baloosearch"

// defaultLimit 是单次查询的默认最大结果数;对齐 baloosearch -l 的语义。
const defaultLimit = 200

// --- 载荷类型(对应 manifest tools 的 JSON schema)---

// SearchFileArgs 是 search_files 的入参。
//   - Query 必填,非空字符串;Baloo 查询语言元字符(`content:`/`filename:`)透传;
//   - Dir 可选,绝对路径,形态校验后作为 baloosearch -d 入参;
//   - Mimetype 可选,须是合法 `type/subtype`(经 mime.ParseMediaType);
//   - Since/Until 可选,RFC3339 形态,客户端二次按文件 mtime 过滤;
//   - SizeMin/SizeMax 可选,字节数(>=0),客户端二次按 stat 过滤。
type SearchFileArgs struct {
	Query    string `json:"query"`
	Dir      string `json:"dir,omitempty"`
	Mimetype string `json:"mimetype,omitempty"`
	Since    string `json:"since,omitempty"`
	Until    string `json:"until,omitempty"`
	SizeMin  *int64 `json:"size_min,omitempty"`
	SizeMax  *int64 `json:"size_max,omitempty"`
}

// FileHit 是 search_files 的单条结果。URL 是 Baloo 返的 file:// URL,
// Path 是 URL 反归一化的本地绝对路径;Mimetype/Size/Mtime 由 stat 二次探查
// 填入(若文件不可达则置零值)。
type FileHit struct {
	URL      string  `json:"url"`
	Path     string  `json:"path"`
	Mimetype string  `json:"mimetype,omitempty"`
	Size     int64   `json:"size,omitempty"`
	Mtime    string  `json:"mtime,omitempty"`
	Rating   float64 `json:"rating,omitempty"`
}

// FileSearchResult 是 search_files 的返回。Files 永为非 nil 空切片
// (空集不 wire 成 null);Note 承载降级原因。
type FileSearchResult struct {
	Files []FileHit `json:"files"`
	Count int       `json:"count"`
	Note  string    `json:"note,omitempty"`
}

// ContentSearchArgs 是 search_content 的入参。query 透传 Baloo 查询语言。
type ContentSearchArgs struct {
	Query string `json:"query"`
	Dir   string `json:"dir,omitempty"`
}

// ContentHit 是 search_content 的单条结果。Baloo 无 snippet 行格式,只列
// 文件路径,与 FileHit 同 URL/Path 字段。
type ContentHit struct {
	URL  string `json:"url"`
	Path string `json:"path"`
}

// ContentSearchResult 是 search_content 的返回。Files 永为非 nil 空切片。
type ContentSearchResult struct {
	Files []ContentHit `json:"files"`
	Count int          `json:"count"`
	Note  string       `json:"note,omitempty"`
}

// ReindexArgs 是 search_reindex 的入参。L1 deferred:Dir 仅回显,不执行。
type ReindexArgs struct {
	Dir string `json:"dir,omitempty"`
}

// ReindexResult 是 search_reindex 的返回。Started 恒 false。
type ReindexResult struct {
	Started bool   `json:"started"`
	Dir     string `json:"dir,omitempty"`
	Note    string `json:"note"`
}

// --- 参数校验 ---

// searchDirPatternString 是 dir 形态白名单字面量:必须绝对路径,不含控制
// 字符/空字节。
const searchDirPatternString = `^/[^\x00-\x1f\x7f]+$`

var searchDirPattern = regexp.MustCompile(searchDirPatternString)

// validateSearchQuery 校验 query:非空、无控制字符、无空字节。
// 透传 Baloo 查询语言(支持 `content:` `filename:` 等),不做形状限制。
func validateSearchQuery(q string) error {
	if q == "" {
		return errors.New("query 不能为空")
	}
	if strings.ContainsRune(q, 0) {
		return errors.New("query 含空字节")
	}
	if strings.ContainsAny(q, "\r\n\t\f\v") {
		return errors.New("query 含控制字符")
	}
	return nil
}

// validateSearchDir 校验 dir:必须绝对、词法合法,不含 `..` / 空白 / shell
// 元字符 / 前导 `-`。本插件不读 dir 内容,仅把它作为 baloosearch -d 入参;
// 故校验强度对齐 smart 家族的 argv 直发防注入(没有 shell 包装,但前导 `-`
// 仍可能让 baloosearch 把 token 当选项)。空串视为可选省略。
func validateSearchDir(dir string) error {
	if dir == "" {
		return nil
	}
	if strings.ContainsRune(dir, 0) {
		return errors.New("dir 含空字节")
	}
	if strings.ContainsAny(dir, " \t\n\r\f\v") {
		return errors.New("dir 含空白字符")
	}
	if strings.Contains(dir, "..") {
		return errors.New("dir 含目录遍历序列 ..")
	}
	if strings.HasPrefix(dir, "-") {
		return errors.New("dir 不能以 - 开头(选项注入)")
	}
	if strings.ContainsAny(dir, ";`$|*?<>{}[]\\'\"~!#&") {
		return errors.New("dir 含 shell 元字符")
	}
	if !filepath.IsAbs(dir) {
		return errors.New("dir 必须是绝对路径")
	}
	if !searchDirPattern.MatchString(dir) {
		return fmt.Errorf("dir=%q 不在绝对路径白名单", dir)
	}
	return nil
}

// validateMimetype 校验 mimetype:经 mime.ParseMediaType 严格解析。
// 不合法或缺 subtype 直接拒绝;空视为可选。
func validateMimetype(mt string) error {
	if mt == "" {
		return nil
	}
	parsed, _, err := mime.ParseMediaType(mt)
	if err != nil {
		return fmt.Errorf("mimetype=%q 不是合法 type/subtype: %w", mt, err)
	}
	if !strings.Contains(parsed, "/") {
		return fmt.Errorf("mimetype=%q 必须含 subtype", mt)
	}
	return nil
}

// validateTimestamp 校验 RFC3339 形态字符串。返回 time.Time(UTC 归一),
// 留作与 stat mtime 比较;空视为未约束(返回零值)。
func validateTimestamp(label, s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s=%q 不是 RFC3339: %w", label, s, err)
	}
	return t.UTC(), nil
}

// validateSize 校验 size(>=0);nil 视为未约束。
func validateSize(label string, v *int64) error {
	if v == nil {
		return nil
	}
	if *v < 0 {
		return fmt.Errorf("%s=%d 不能为负", label, *v)
	}
	return nil
}

// --- baloosearch 路径解析 ---

// resolveBalooSearch 用 exec.LookPath 定位 baloosearch,失败回退默认路径。
// 仿 smart.resolveSmartctl 形态。
func resolveBalooSearch() string {
	if p, err := exec.LookPath("baloosearch"); err == nil && p != "" {
		return p
	}
	return defaultBalooSearch
}

// --- 可移植 CLI runner(对齐 smart/avc 家族)---

// execError 复制自 smart/avc 家族:退出码 + 真 stderr + Cause。
type execError struct {
	Code   int
	Stderr string
	Cause  error
}

func (e *execError) Error() string {
	if e.Stderr != "" {
		return fmt.Sprintf("%s: %s", e.Cause.Error(), strings.TrimSpace(e.Stderr))
	}
	return e.Cause.Error()
}

func (e *execError) Unwrap() error { return e.Cause }

// isMissingBinary 复制自 smart 家族:fs.ErrNotExist / fs.ErrPermission /
// fs.ErrInvalid / exec.ErrNotFound。
func isMissingBinary(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) ||
		errors.Is(err, fs.ErrInvalid) || errors.Is(err, exec.ErrNotFound)
}

// execRunner 是可注入的外部进程执行器。
type execRunner func(ctx context.Context, bin string, stdin io.Reader, onLine func([]byte) bool, args ...string) error

// execHelper argv 直发执行外部进程:逐行回传 stdout,失败包装为 execError。
// cmd.Stderr 必须在 Start() 前接管(否则真 stderr 回宿主 stderr);WaitDelay
// 防止 ctx 取消后子孙进程持有 pipe 阻塞 Wait。
func execHelper(ctx context.Context, bin string, stdin io.Reader, onLine func([]byte) bool, args ...string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = stdin
	cmd.WaitDelay = 2 * time.Second

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("接管 %s stdout 失败: %w", bin, err)
	}

	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		if isMissingBinary(err) {
			return fmt.Errorf("无法启动 %s: %w", bin, err)
		}
		return fmt.Errorf("启动 %s 失败: %w", bin, err)
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if !onLine(sc.Bytes()) {
			break
		}
	}
	scanErr := sc.Err()

	waitErr := cmd.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if scanErr != nil {
		return fmt.Errorf("读取 %s stdout 失败: %w", bin, scanErr)
	}
	if waitErr != nil {
		code := -1
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			code = ee.ExitCode()
		}
		return &execError{
			Code:   code,
			Stderr: stderrBuf.String(),
			Cause:  fmt.Errorf("%s 退出码 %d", filepath.Base(bin), code),
		}
	}
	return nil
}

// --- baloosearch 退出码 → 语义 ---
//
// baloosearch 的退出码沿用 balooctl 家族:
//   rc=0  → 成功,stdout 含结果行;
//   rc=1  → 命令行错误 / 不合法 dir;
//   rc>=2 → 索引访问失败 / Baloo daemon 不可达。
//
// stderr 仅在 daemon 真不可达时写(`Cannot connect to daemon`等),其它路径
// 走 stdout(进度行 `Elapsed: X msecs` 写 stderr,但容错漏 stdout)。本插件
// 以"Stderr 非空 = 真结构失败"为准(对齐 smart 经验)。

// translateBalooError 把 execHelper 错误翻译为 (note, fatal)。
// 返回 fatal=false 的典型情形:
//   - err == nil:成功;
//   - binary 缺失:baloosearch 不可用(未安装 baloo6-tools/kf6-baloo);
//   - execError 且 Stderr 为空:rc>0 但无 stderr,多为"无结果"语义,降级为
//     note + 空集,不 fatal(与 smart 位掩码处理对称)。
//
// 其余 → fatal=true。
func translateBalooError(err error) (note string, fatal bool) {
	if err == nil {
		return "", false
	}
	if isMissingBinary(err) {
		return "baloosearch 不可用(未安装 baloo6-tools/kf6-baloo)", false
	}
	var ee *execError
	if errors.As(err, &ee) {
		if ee.Stderr == "" {
			if ee.Code == 1 {
				return "baloosearch 命令行参数非法或 dir 不存在", false
			}
			return fmt.Sprintf("baloosearch 退出码 %d", ee.Code), false
		}
	}
	return "", true
}

// --- service 层 ---

// balooDBus 抽象"探测 Baloo 在会话 bus 上的可用性"。注入接口便于单测替身:
// 生产 impl 在 dbus.go 用 godbus/v5;tests 用 fakeDBus。D-Bus 客户端不复用
// CLI runner,两条路径独立(本插件架构裁决)。
type balooDBus interface {
	// NameHasOwner 返回目标名是否在本次连接的会话 bus 上。
	NameHasOwner(name string) (bool, error)
	// IndexingEnabled 返回 org.kde.baloo.main 上的 IndexingEnabled 属性。
	IndexingEnabled() (bool, error)
	Close() error
}

// dBusAvailability 是探测结果快照(给 note 用)。
type dBusAvailability struct {
	reachable       bool
	nameOwned       bool
	indexingEnabled bool
}

// service 持有 D-Bus 客户端 + baloosearch CLI runner。connect 与 run 都可注入;
// connect 默认生产 impl(见 dbus.go),单测 fake;run 默认 execHelper,单测 fakeRunner。
type service struct {
	connect func() (balooDBus, error)
	run     execRunner
	binary  string
	timeout time.Duration
}

// newService 装配默认 service(production)。
func newService() *service {
	return &service{
		connect: defaultDBusConnect,
		run:     execHelper,
		binary:  resolveBalooSearch(),
		timeout: searchTimeout,
	}
}

// runBalooSearch 跑 baloosearch 并收集 stdout 路径。
func (s *service) runBalooSearch(ctx context.Context, args ...string) ([][]byte, error) {
	execCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	var lines [][]byte
	err := s.run(execCtx, s.binary, nil, func(b []byte) bool {
		lines = append(lines, append([]byte(nil), b...))
		return true
	}, args...)
	return lines, err
}

// probe 是 D-Bus 可用性探测:开连接、取 NameHasOwner、取 IndexingEnabled。
// 任意一步失败都返回 (probe{}, err 或不可达 note),**不 panic**。
func (s *service) probe() (balooDBus, dBusAvailability, error) {
	conn, err := s.connect()
	if err != nil {
		return nil, dBusAvailability{}, err
	}
	avail := dBusAvailability{reachable: true}
	owned, err := conn.NameHasOwner("org.kde.baloo")
	if err != nil {
		_ = conn.Close()
		return nil, avail, fmt.Errorf("查询 org.kde.baloo 是否注册失败: %w", err)
	}
	avail.nameOwned = owned
	if owned {
		if v, err := conn.IndexingEnabled(); err != nil {
			avail.indexingEnabled = false
		} else {
			avail.indexingEnabled = v
		}
	}
	return conn, avail, nil
}

// parseBalooPaths 把 baloosearch 的 stdout 逐行解析为 file:// URL。
// baloosearch 的非路径行(空行、`Elapsed:`、`Error:`)被忽略。
func parseBalooPaths(lines [][]byte) []string {
	var paths []string
	for _, line := range lines {
		s := strings.TrimSpace(string(line))
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "Elapsed:") {
			continue
		}
		if strings.HasPrefix(s, "Error:") || strings.HasPrefix(s, "error:") {
			continue
		}
		paths = append(paths, pathToFileURL(s))
	}
	return paths
}

// pathToFileURL 把本地绝对路径转 file:// URL。已含 `file://` 前缀则原样。
// 用 url.URL{Scheme,Path} 直接构造而非 PathEscape(PathEscape 会连 `/` 一并
// 转义,生成 `file://%2F...` 而非 `file:///...`)。
func pathToFileURL(p string) string {
	if strings.HasPrefix(p, "file://") {
		return p
	}
	clean := filepath.Clean(p)
	return (&url.URL{Scheme: "file", Path: clean}).String()
}

// fileURLToPath 把 file:// URL 反归一化为本地绝对路径。形态非法时返回空串。
func fileURLToPath(u string) string {
	if !strings.HasPrefix(u, "file://") {
		return ""
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	if parsed.Path == "" {
		return ""
	}
	return parsed.Path
}

// hitWithStat 给一条 URL 加 stat:实际 stat 文件取 mtime/size,按 since/until
// 与 size 范围二次过滤。stat 失败(missing/perm)→ 保留 URL/Path(容错),
// Mtime/Size 置零值;若 since/until/size 有约束且 stat 失败,保守跳过。
func hitWithStat(u string, since, until *time.Time, sizeMin, sizeMax *int64) (FileHit, bool) {
	p := fileURLToPath(u)
	if p == "" {
		return FileHit{}, false
	}
	h := FileHit{URL: u, Path: p}
	info, err := os.Stat(p)
	if err != nil {
		// 无过滤约束时,容错返回(不阻塞 Baloo 侧已确认存在的行);
		// 有约束时保守跳过(不误报)。
		if since.IsZero() && until.IsZero() && sizeMin == nil && sizeMax == nil {
			return h, true
		}
		return h, false
	}
	h.Size = info.Size()
	mt := info.ModTime().UTC()
	h.Mtime = mt.Format(time.RFC3339)

	if !since.IsZero() && mt.Before(*since) {
		return h, false
	}
	if !until.IsZero() && mt.After(*until) {
		return h, false
	}
	if sizeMin != nil && h.Size < *sizeMin {
		return h, false
	}
	if sizeMax != nil && h.Size > *sizeMax {
		return h, false
	}
	return h, true
}

// --- 工具实现 ---

// SearchFiles search_files 工具实现。流程:
//  1. 参数校验(query / dir / mimetype / since / until / size 范围);
//  2. D-Bus probe → 失败/不可达 → 降级空集(不 panic);
//  3. fork baloosearch 收集 stdout 路径;
//  4. stat + 客户端侧过滤(mtime / size);按 defaultLimit 截断;
//  5. 汇成 FileSearchResult。Note 字段透明记录降级原因。
//
// Mimetype 过滤:不额外 fork `file --mime-type` 避免多余 exec;
// Baloo 已在索引里带 mimetype,但 baloosearch stdout 不回传,故不做
// 客户端二次过滤,mimetype 形参仅做形态校验后作为 note 提示。
func (s *service) SearchFiles(ctx context.Context, args SearchFileArgs) (FileSearchResult, error) {
	if err := validateSearchQuery(args.Query); err != nil {
		return FileSearchResult{}, err
	}
	if err := validateSearchDir(args.Dir); err != nil {
		return FileSearchResult{}, err
	}
	if err := validateMimetype(args.Mimetype); err != nil {
		return FileSearchResult{}, err
	}
	since, err := validateTimestamp("since", args.Since)
	if err != nil {
		return FileSearchResult{}, err
	}
	until, err := validateTimestamp("until", args.Until)
	if err != nil {
		return FileSearchResult{}, err
	}
	if err := validateSize("size_min", args.SizeMin); err != nil {
		return FileSearchResult{}, err
	}
	if err := validateSize("size_max", args.SizeMax); err != nil {
		return FileSearchResult{}, err
	}
	if args.SizeMin != nil && args.SizeMax != nil && *args.SizeMin > *args.SizeMax {
		return FileSearchResult{}, fmt.Errorf("size_min=%d 大于 size_max=%d", *args.SizeMin, *args.SizeMax)
	}

	res := FileSearchResult{Files: []FileHit{}}

	conn, avail, err := s.probe()
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		res.Note = fmt.Sprintf("D-Bus session bus 不可达,Baloo 不可用: %v", err)
		return res, nil
	}
	if !avail.nameOwned {
		res.Note = "Baloo D-Bus 服务 org.kde.baloo 未注册,Baloo 不可用"
		return res, nil
	}
	if !avail.indexingEnabled {
		res.Note = "Baloo org.kde.baloo.main.IndexingEnabled=false;索引未启用"
		return res, nil
	}

	balArgs := []string{"-l", strconv.Itoa(defaultLimit)}
	if args.Dir != "" {
		balArgs = append(balArgs, "-d", args.Dir)
	}
	balArgs = append(balArgs, args.Query)
	lines, runErr := s.runBalooSearch(ctx, balArgs...)
	note, fatal := translateBalooError(runErr)
	if fatal {
		return FileSearchResult{}, fmt.Errorf("search_files 失败: %w", runErr)
	}
	if note != "" {
		res.Note = note
	}

	urls := parseBalooPaths(lines)
	for _, u := range urls {
		h, keep := hitWithStat(u, &since, &until, args.SizeMin, args.SizeMax)
		if !keep {
			continue
		}
		res.Files = append(res.Files, h)
		if len(res.Files) >= defaultLimit {
			break
		}
	}
	res.Count = len(res.Files)
	return res, nil
}

// SearchContent search_content 工具实现。流程与 SearchFiles 对称,但跳过
// mtime/size 过滤(Baloo content 查询语义近"包含关系",与文件级过滤耦合即
// 弱)。Note 透传降级原因。
func (s *service) SearchContent(ctx context.Context, args ContentSearchArgs) (ContentSearchResult, error) {
	if err := validateSearchQuery(args.Query); err != nil {
		return ContentSearchResult{}, err
	}
	if err := validateSearchDir(args.Dir); err != nil {
		return ContentSearchResult{}, err
	}
	res := ContentSearchResult{Files: []ContentHit{}}

	conn, avail, err := s.probe()
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		res.Note = fmt.Sprintf("D-Bus session bus 不可达,Baloo 不可用: %v", err)
		return res, nil
	}
	if !avail.nameOwned {
		res.Note = "Baloo D-Bus 服务 org.kde.baloo 未注册,Baloo 不可用"
		return res, nil
	}
	if !avail.indexingEnabled {
		res.Note = "Baloo 索引未启用(org.kde.baloo.main.IndexingEnabled=false),全文搜索不可用"
		return res, nil
	}

	balArgs := []string{"-l", strconv.Itoa(defaultLimit)}
	if args.Dir != "" {
		balArgs = append(balArgs, "-d", args.Dir)
	}
	balArgs = append(balArgs, args.Query)
	lines, runErr := s.runBalooSearch(ctx, balArgs...)
	note, fatal := translateBalooError(runErr)
	if fatal {
		return ContentSearchResult{}, fmt.Errorf("search_content 失败: %w", runErr)
	}
	if note != "" {
		res.Note = note
	}

	urls := parseBalooPaths(lines)
	for _, u := range urls {
		p := fileURLToPath(u)
		if p == "" {
			continue
		}
		res.Files = append(res.Files, ContentHit{URL: u, Path: p})
		if len(res.Files) >= defaultLimit {
			break
		}
	}
	res.Count = len(res.Files)
	return res, nil
}

// Reindex search_reindex 工具实现。L1 deferred:不 fork baloosearch,
// 不调 daedalus-tx/confirm_token,不动任何系统状态。Started 恒 false,Note
// 透传回显参数(供 LLM 引用,避免误以为已触发)。Baloo 不可用时额外提示。
func (s *service) Reindex(_ context.Context, args ReindexArgs) (ReindexResult, error) {
	if err := validateSearchDir(args.Dir); err != nil {
		return ReindexResult{}, err
	}
	note := "L1 deferred;重建索引需 y/n 确认令牌(daedalus-tx/confirm_token),当前未启用;未触发任何 Baloo/baloosearch/balooctl I/O"
	// 顺带探测 Baloo 可用性(不 fork,仅 D-Bus),补充提示。
	if conn, err := s.connect(); err == nil {
		defer conn.Close()
		if owned, err := conn.NameHasOwner("org.kde.baloo"); err == nil && !owned {
			note = "L1 deferred + Baloo 不可用:org.kde.baloo 未注册"
		} else if err != nil {
			note = "L1 deferred + Baloo 不可用:D-Bus session bus 不可达"
		}
	} else {
		note = "L1 deferred + Baloo 不可用:D-Bus session bus 不可达"
	}
	return ReindexResult{
		Dir:     args.Dir,
		Started: false,
		Note:    note,
	}, nil
}
