// integrity 只读基元:直 fork rpm -V 解析 rpm 数据库与磁盘文件的一致性,返回
// 类型化差异列表/未改包列表/总体统计。
//
// 安全边界:参数(package/limit/offset)在拼 argv 前强制校验(字符集白名单 +
// 数值边界 + 互斥检查),再经绝对路径 argv 直发 rpm;never shell。环境变量
// LC_ALL=C 显式注入(force C 输出),把行错位(missing/未改动的 9 字节
// 标志位)锁定到英文,跨 locale 解析稳定。rpm 缺失或非 root 启动期 euid 检
// 查失败一律空集 + 显式 note。
//
// 退出码语义谱(本机 rpm 4.16.1.3 实测):
//   - 0      : 验证完成(全匹配或有差异都在 stdout 上)。本实测下场 与文档
//     "rc=1=有差异"不同;Linux rpm 4.16 产出始终 rc=0,与上游 rpm 5.x
//     出现分歧。代码防御性 parse stdout,rc 1/2+ 区分故障类型上抛给调用方
//     决定。
//   - 1      : 包未安装("package X is not installed")或文档语义的"有差异";
//     包装成 *execError{Code:1,Stderr} 交 handleExecError 统一分类为非致命
//     note,各工具按已收集的 stdout 继续解析(绝不 abort)。
//   - ≥2     : 真故障(DB 损坏 / 不可读),handleExecError 判 fatal,wrap
//     *execError{Code,Stderr} 上抛,不吞(全量与单包形态一视同仁)。
//   - ctxErr : DeadlineExceeded/Canceled 一律优先于 Wait 返回值(参
//     journal 模板的 ctx 到期语义)。
//
// 命名空间口径:rpm 包 NAME(不是 NEVRA)。`rpm -qf <path>` 缺省输出 NEVRA
// (如 setup-2.13.7-10.el9.noarch),与 `rpm -qa --queryformat '%{NAME}\n'`
// 的 NAME(setup)不同命名空间;归属查询一律带 --queryformat '%{NAME}\n',
// 集合比对才可能命中。
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// rpmBinary 是 rpm 二进制的绝对路径;包级变量便于测试用 t.TempDir() 假脚
// 本注入。
var rpmBinary = "/usr/bin/rpm"

const (
	// rpmTimeout 是 Verify/Unchanged/Summary 调用方施加的兜底超时;rpm 验
	// 证通常很快,但 -Va 在大包集群上可能数秒到十秒,30s 是合理上限。
	rpmTimeout = 30 * time.Second

	// verifyDefaultLimit / verifyMaxLimit / verifyDefaultOffset 是 rpm_verify
	// / rpm_unchanged 的 limit/offset 边界。最大上限明确条数(防止拉爆
	// 内存),缺省上限与 trace/audit 家族对齐。
	verifyDefaultLimit = 1000
	verifyMaxLimit     = 10000

	// summaryDefaultTopN 是 SummaryResult.ChangedPackagesTop 的截断阈值;
	// 大量被改包时只回显前 N 个 + 总数。
	summaryDefaultTopN = 50

	// nameQueryFormat 是统一 NAME 查询格式:rpm 在 -qf/-qa 下缺省输出
	// NEVRA(`setup-2.13.7-10.el9.noarch`),与 NAME 集合(全集 - 已改集)
	// 不同集合,让"全量包 - 归属配"比对永不命中。统一带 `nameQueryFormat`
	// 才使两路名字落到同一命名空间(参包头注释)。
	nameQueryFormat = "%{NAME}\n"
)

// packagePattern 是 package 名的字符集白名单:首字符必须是字母/数字/下划线
// (天然排除前导 '-' 选项注入与空串),其余允许字母/数字/下划线/点/@/+/-/,
// ';'、'/'、空白、shell 元字符均被拒。".." 遍历由 Validate 单独兜底。
var packagePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@+-]*$`)

// typeMarkers 是 rpm verify 输出的类型标记字符集合:c=config, d=doc,
// l=license, r=readme, g=ghost。空格(归类表)不属于此集合。
const typeMarkers = "cdlrg"

// verifyFlagChars 是 rpm verify 9 字节属性位矩阵的合法字符集合:每字节要么是
// '.',要么是 '?',要么是下列差异位字符之一。不同 rpm 版本/发行版对第 9 位
// 有 'P'(capabilities)与 'C'(部分版本的兼容写法)两种;一并识别。
const verifyFlagChars = "SM5DLUGTPC"

// --- 退出码 / 包装 ---

// execError 是 rpm 非零退出的类型化包装:Code 是子进程真实退出码,Stderr 是
// 子进程 stderr 内容(可能为空);Cause 是 Wait 返回的 *ExitError 或
// *fs.PathError。调用方可用 errors.As 取出 Code 决定按"已安装列表差异"语义
// 还是真故障上抛。
type execError struct {
	Code   int    // 子进程退出码(> 0)
	Stderr string // 子进程 stderr 内容(可能为空)
	Cause  error  // 底层错误
}

func (e *execError) Error() string {
	return fmt.Sprintf("rpm 退出码 %d: %s", e.Code, strings.TrimSpace(e.Stderr))
}

func (e *execError) Unwrap() error { return e.Cause }

// isMissingBinary 识别"rpm 不在"的 ENOENT 降级信号。
func isMissingBinary(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, exec.ErrNotFound)
}

// isPackageNotInstalled 识别 rpm 的"包不存在"stderr 模式(任意 locale 下
// "X is not installed" 子串足够跨 i18n 命中);调用方决定按 note / 空集
// 处理而非上抛。
func isPackageNotInstalled(stderr string) bool {
	s := strings.ToLower(strings.TrimSpace(stderr))
	return strings.Contains(s, "is not installed")
}

// isUnownedMessage 识别 rpm -qf 对无归属文件的告警行(LC_ALL=C 下整行
// "file /x is not owned by any package");该行误碰 NAME 集合会污染
// 已改包,必须排除。先前实现用 HasSuffix("not owned") 命中不上该行,导致
// 误把无归属文件当成某个"unknown"包加入 changed 集(违规)。
func isUnownedMessage(s string) bool {
	return strings.Contains(s, "is not owned")
}

// handleExecError 收敛 rpm runner 错误的语义分类:rpm 缺失与 rc=1(包未安装 /
// 报告差异)非 fatal,降级为 note 交调用方按 stdout 继续;rc≥2 或非 *execError
// 视为真故障,fatal=true 上抛。
//
// 调用方约定:err != nil 且 !fatal 时不得把结果宣称为"干净 / 未改"——rc=1 已
// 声明存在差异;rpm 缺失时收集到的行必为空(注入 fake runner 时不在管辖)。
func handleExecError(err error) (note string, fatal bool) {
	if err == nil {
		return "", false
	}
	if isMissingBinary(err) {
		return "rpm 不可用: " + err.Error(), false
	}
	var ee *execError
	if !errors.As(err, &ee) || ee.Code >= 2 {
		return "", true
	}
	// rc=1:"包未安装" 或文档语义"报告差异",两者都按已收集的 stdout 继续
	// 解析,但 note 文案区分,免得误导调用方去找不存在的包。
	if isPackageNotInstalled(ee.Stderr) {
		return "包不存在: " + strings.TrimSpace(ee.Stderr), false
	}
	return "rpm 报告差异(退出码 1),已按 stdout 解析", false
}

// mergeNotes 合并非空 note;空串跳过,重复同串去重,其余以 "; " 连接。
// 截断/降级等多源 note 拼接的通用入口,避免每次手写 strings.TrimSpace+Join
// 漂移。
func mergeNotes(notes ...string) string {
	var kept []string
	for _, n := range notes {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		dup := false
		for _, k := range kept {
			if k == n {
				dup = true
				break
			}
		}
		if !dup {
			kept = append(kept, n)
		}
	}
	return strings.Join(kept, "; ")
}

// --- 载荷类型 ---

// VerifyFlags 是 rpm verify 9 字节属性位矩阵的类型化展开:每位匹配到位字符
// 才置 true。Unreadable 表示任意位为 '?'(rpm 无法读该属性,通常因 EACCES),
// Missing 表示行是 missing 文件缺失形式而非 9 字节矩阵。
type VerifyFlags struct {
	Size       bool `json:"size"`       // S - 大小
	Mode       bool `json:"mode"`       // M - 模式/权限
	MD5        bool `json:"md5"`        // 5 - 摘要
	Device     bool `json:"device"`     // D - 设备号
	Symlink    bool `json:"symlink"`    // L - symlink 目标
	User       bool `json:"user"`       // U - 属主
	Group      bool `json:"group"`      // G - 属组
	Mtime      bool `json:"mtime"`      // T - mtime
	Caps       bool `json:"caps"`       // P - capabilities
	Unreadable bool `json:"unreadable"` // 任一位 '?'(不可读)
	Missing    bool `json:"missing"`    // 行是 "missing <path>" 形态
}

// VerifyResult 是单条文件差异的类型化视图:rpm -V 输出每行 → 一个 VerifyResult。
// Package 在 rpm_verify(all=true) 形态下可能为空(逐行不附包名,需要 rpm -qf
// 二次查;为控制 fork 数量,默认留空)。
type VerifyResult struct {
	Package string      `json:"package,omitempty"`
	Path    string      `json:"path"`
	Type    string      `json:"type,omitempty"`
	Flags   VerifyFlags `json:"flags"`
}

// VerifyResultPage 是 rpm_verify 的返回载荷:TotalLines 是 rpm 原始输出总
// 条数,Returned 是本次实际返回条数,Truncated 表示被分页截断;Note 承载
// 截断/降级等人类可读说明(无异常时为空)。
type VerifyResultPage struct {
	Entries    []VerifyResult `json:"entries"`
	TotalLines int            `json:"total_lines"`
	Returned   int            `json:"returned"`
	Truncated  bool           `json:"truncated"`
	Note       string         `json:"note,omitempty"`
}

// VerifyArgs 是 rpm_verify 的已校验入参;指针字段区分"未给"与"给空"。
// Package 与 All 二选一:同时给则 rule 报错冲突。
type VerifyArgs struct {
	Package *string
	All     bool
	Limit   *int
	Offset  *int
}

// Validate 校验 rpm_verify 入参并补全 limit/offset 缺省。一切拒绝发生在拼
// argv 之前——非法输入永不抵达 exec(rpm 自身参数注入面)。校验顺序:先 package
// 字符串合法(含注入/遍历拒绝),再互斥检查,再 limit/offset 边界。
func (a *VerifyArgs) Validate() error {
	if a.Package != nil {
		if err := validatePackage(*a.Package); err != nil {
			return err
		}
	}
	if a.Package == nil && !a.All {
		return errors.New("必须指定 package 或 all=true")
	}
	if a.Package != nil && a.All {
		return errors.New("package 与 all 不能同时指定")
	}
	if a.Limit == nil {
		def := verifyDefaultLimit
		a.Limit = &def
	} else if *a.Limit < 1 || *a.Limit > verifyMaxLimit {
		return fmt.Errorf("limit 必须在 1..%d 之间, got %d", verifyMaxLimit, *a.Limit)
	}
	if a.Offset == nil {
		zero := 0
		a.Offset = &zero
	} else if *a.Offset < 0 {
		return fmt.Errorf("offset 必须 >= 0, got %d", *a.Offset)
	}
	return nil
}

// UnchangedArgs 是 rpm_unchanged 的入参:Package 可选(单包 / 全部;三种;
// Package 全集合 → list 模式分页)。
type UnchangedArgs struct {
	Package *string
	Limit   *int
	Offset  *int
}

// Validate 校验 rpm_unchanged 入参并补全 limit/offset 缺省。
func (a *UnchangedArgs) Validate() error {
	if a.Package != nil {
		if err := validatePackage(*a.Package); err != nil {
			return err
		}
	}
	if a.Limit == nil {
		def := verifyDefaultLimit
		a.Limit = &def
	} else if *a.Limit < 1 || *a.Limit > verifyMaxLimit {
		return fmt.Errorf("limit 必须在 1..%d 之间, got %d", verifyMaxLimit, *a.Limit)
	}
	if a.Offset == nil {
		zero := 0
		a.Offset = &zero
	} else if *a.Offset < 0 {
		return fmt.Errorf("offset 必须 >= 0, got %d", *a.Offset)
	}
	return nil
}

// validatePackage 拒绝注入与遍历,守住 null + Name 边界。
func validatePackage(p string) error {
	if p == "" {
		return fmt.Errorf("非法 package: 空字符串")
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("非法 package(路径遍历): %q", p)
	}
	if !packagePattern.MatchString(p) {
		return fmt.Errorf("非法 package: %q", p)
	}
	return nil
}

// UnchangedResult 是 rpm_unchanged 的返回载荷:未改的包名列表 + 分页统计 +
// Note。
type UnchangedResult struct {
	Packages   []string `json:"packages"`
	TotalLines int      `json:"total_lines"`
	Returned   int      `json:"returned"`
	Truncated  bool     `json:"truncated"`
	Note       string   `json:"note,omitempty"`
}

// SummaryResult 是 rpm_summary 的返回载荷:总包数 / 被改包数 / 被改文件数 +
// 被改包名列表(前 N 个)+ Note。
type SummaryResult struct {
	TotalPackages       int      `json:"total_packages"`
	ChangedPackages     int      `json:"changed_packages"`
	ChangedFiles        int      `json:"changed_files"`
	ChangedPackagesTop  []string `json:"changed_packages_top,omitempty"`
	ChangedPackagesMore int      `json:"changed_packages_more,omitempty"`
	Note                string   `json:"note,omitempty"`
}

// --- service / runner ---

// execRunner 是外部 CLI 调用的注入点:逐行喂给 onLine,onLine 返回 false 时
// 须中止子进程并正常收工。生产实现是 runRPM。
type execRunner func(ctx context.Context, onLine func([]byte) bool, args ...string) error

// service 持有 CLI 调用器与调用方超时;测试以替身装配。
type service struct {
	run        execRunner
	rpmTimeout time.Duration
}

// newService 装配生产 service:真 fork rpm,30s 超时上限。
func newService() *service {
	return &service{run: runRPM, rpmTimeout: rpmTimeout}
}

// Verify 执行 rpm_verify:单包走 `rpm -V <pkg>`,全量走 `rpm -Va` + 分页。
// 单包与全量形态合流到同一行收割 + parseVerifyOutput;rc 语义集中由
// handleExecError 决定 fatal 与 note(不再分头 "could be rc=1 / rc≥2")。
func (s *service) Verify(ctx context.Context, args VerifyArgs) (VerifyResultPage, error) {
	if err := args.Validate(); err != nil {
		return VerifyResultPage{}, err
	}
	execCtx, cancel := context.WithTimeout(ctx, s.rpmTimeout)
	defer cancel()

	var (
		argv []string
		echo string // 写入每条 Entry.Package 的包名,全量形态留空
	)
	if args.Package != nil {
		argv = []string{"-V", *args.Package}
		echo = *args.Package
	} else {
		argv = []string{"-Va"}
	}

	// 收集原始行后由 visiblePage 切片;不依赖 rpm -V 是否遵守 --limit
	// (rpm 不支持 --limit) —— 只能在应用层收割。
	var lines [][]byte
	execNote := ""
	err := s.run(execCtx, func(line []byte) bool {
		lines = append(lines, append([]byte(nil), line...))
		return true
	}, argv...)
	if err != nil {
		note, fatal := handleExecError(err)
		if fatal {
			return VerifyResultPage{}, err
		}
		execNote = note
	}

	entries, skipped := parseVerifyOutput(lines)
	_ = skipped // 留作对内可观察:解析失败行不破坏整体输出,但用户层暂未暴露。
	page := visiblePage(entries, *args.Limit, *args.Offset, echo)
	if execNote != "" {
		page.Note = mergeNotes(execNote, page.Note)
	}
	return page, nil
}

// visiblePage 按 limit/offset 切片并填充分页统计。
func visiblePage(in []VerifyResult, limit, offset int, echo string) VerifyResultPage {
	page := VerifyResultPage{
		Entries:    []VerifyResult{}, // 显式空切片保证 wire 上是 "[]" 不是 "null"
		TotalLines: len(in),
	}
	for _, e := range in {
		if echo != "" && e.Package == "" {
			e.Package = echo
		}
		if offset > 0 {
			offset--
			continue
		}
		if page.Returned >= limit {
			page.Truncated = true
			continue
		}
		page.Entries = append(page.Entries, e)
		page.Returned++
	}
	if page.Truncated {
		page.Note = fmt.Sprintf("输出超过 limit=%d,已截断", limit)
	}
	return page
}

// Unchanged 执行 rpm_unchanged:单包走 `rpm -V <pkg>`(空输出 = 未改);全量
// 走 `rpm -qa` + `rpm -Va` + 归属集 - 已改集 = 未改集。
func (s *service) Unchanged(ctx context.Context, args UnchangedArgs) (UnchangedResult, error) {
	if err := args.Validate(); err != nil {
		return UnchangedResult{}, err
	}
	execCtx, cancel := context.WithTimeout(ctx, s.rpmTimeout)
	defer cancel()

	if args.Package != nil {
		// 单包形态:跑一次 rpm -V,空输出 = 未改,有输出 = 已改。
		var lines [][]byte
		execNote := ""
		err := s.run(execCtx, func(line []byte) bool {
			lines = append(lines, append([]byte(nil), line...))
			return true
		}, "-V", *args.Package)
		if err != nil {
			note, fatal := handleExecError(err)
			if fatal {
				return UnchangedResult{}, err
			}
			execNote = note
		}
		res := UnchangedResult{
			Packages:   []string{},
			TotalLines: len(lines),
			Note:       execNote,
		}
		// 仅在 rpm 干净退出且无输出时判"未改";rc=1(有差异)或 rpm 缺失时
		// 不得宣称该包未改(handleExecError 的调用方约定)。
		if err == nil && len(lines) == 0 {
			res.Packages = []string{*args.Package}
			res.Returned = 1
		}
		return res, nil
	}

	// 全量形态:`rpm -Va` + `rpm -qf` 归属 → 未改 = 全集 - 已改集。两路
	// note 并存(-Va 与 -qa)合并去重后随 res 返回。
	changed := make(map[string]struct{})
	_, noteA, err := s.collectChangedPackages(ctx, changed)
	if err != nil {
		return UnchangedResult{}, err
	}
	allPkgs, noteB, err := s.collectAllPackages(ctx)
	if err != nil {
		return UnchangedResult{}, err
	}

	unchanged := make([]string, 0, len(allPkgs)-len(changed))
	for _, p := range allPkgs {
		if _, isChanged := changed[p]; !isChanged {
			unchanged = append(unchanged, p)
		}
	}
	res := visibleUnchanged(unchanged, *args.Limit, *args.Offset)
	res.Note = mergeNotes(noteA, noteB, res.Note)
	return res, nil
}

// visibleUnchanged 对 unchanged 包名做分页。
func visibleUnchanged(in []string, limit, offset int) UnchangedResult {
	res := UnchangedResult{
		Packages:   []string{},
		TotalLines: len(in),
	}
	for _, p := range in {
		if offset > 0 {
			offset--
			continue
		}
		if res.Returned >= limit {
			res.Truncated = true
			continue
		}
		res.Packages = append(res.Packages, p)
		res.Returned++
	}
	if res.Truncated {
		res.Note = fmt.Sprintf("输出超过 limit=%d,已截断", limit)
	}
	return res
}

// Summary 走全量概览:`rpm -qa` 取总包数,`rpm -Va` 取差异行,`rpm -qf` 取每
// 个差异文件归属,统计被改包数/文件数 + 被改包名前 N 个。-Va 超时/中断时
// 降级返回 total_packages + note(timeout),而非上抛错误。
func (s *service) Summary(ctx context.Context) (SummaryResult, error) {
	execCtx, cancel := context.WithTimeout(ctx, s.rpmTimeout)
	defer cancel()

	allPkgs, noteA, err := s.collectAllPackages(execCtx)
	if err != nil {
		return SummaryResult{}, err
	}

	// 收集差异文件并归属到包;容错路径:VA 命令超时/中断时降级为
	// total_packages + note(timeout),不返回错误。-Va rc=1 由 collectChangedPackages
	// 内部按 handleExecError 处理为"报告差异,已按 stdout 解析"非致命 note。
	changedPkgs := make(map[string]struct{})
	diffCount, noteB, vaErr := s.collectChangedPackages(execCtx, changedPkgs)
	if vaErr != nil {
		// ctx 超时/中断:rpm -Va 在大包集群上可能耗时数分钟,超时属预期内降
		// 级场景,返回 total_packages + note 而非错误。
		if errors.Is(vaErr, context.DeadlineExceeded) || errors.Is(vaErr, context.Canceled) {
			return SummaryResult{
				TotalPackages: len(allPkgs),
				Note:          mergeNotes(noteA, "rpm -Va 超时或中断,差异统计不完整"),
			}, nil
		}
		return SummaryResult{}, vaErr
	}

	res := SummaryResult{
		TotalPackages:   len(allPkgs),
		ChangedPackages: len(changedPkgs),
		ChangedFiles:    diffCount,
		Note:            mergeNotes(noteA, noteB),
	}
	// 填充 topN + more
	if len(changedPkgs) > summaryDefaultTopN {
		res.ChangedPackagesTop = pickTopN(changedPkgs, summaryDefaultTopN)
		res.ChangedPackagesMore = len(changedPkgs) - summaryDefaultTopN
	} else if len(changedPkgs) > 0 {
		res.ChangedPackagesTop = pickTopN(changedPkgs, len(changedPkgs))
	}
	return res, nil
}

// collectAllPackages 收集所有已安装包 NAME(`rpm -qa --queryformat '%{NAME}\n'`),
// 按首次出现去重:multilib/kernel 等同一 NAME 多实例会重复出现,不去重会让
// TotalPackages 大于现实包种类数(Summary I2)。返回 rpm 非致命 note 供上游
// 与其它源合并。
func (s *service) collectAllPackages(ctx context.Context) ([]string, string, error) {
	execCtx, cancel := context.WithTimeout(ctx, s.rpmTimeout)
	defer cancel()
	var pkgs []string
	seen := make(map[string]bool)
	err := s.run(execCtx, func(line []byte) bool {
		pkg := strings.TrimSpace(string(line))
		if pkg != "" && !seen[pkg] {
			seen[pkg] = true
			pkgs = append(pkgs, pkg)
		}
		return true
	}, "-qa", "--queryformat", nameQueryFormat)
	if err != nil {
		note, fatal := handleExecError(err)
		if fatal {
			return nil, "", err
		}
		return pkgs, note, nil
	}
	return pkgs, "", nil
}

// collectChangedPackages 通过 `rpm -Va` + `rpm -qf --queryformat '%{NAME}\n'`
// 收集被改的包集合,写入传入的 map;返回差异行总数与 rpm 的非致命 note。
// -Va rc=1("报告差异")按 handleExecError 降级为 note 并继续,rc≥2 真故障上抛。
func (s *service) collectChangedPackages(ctx context.Context, out map[string]struct{}) (int, string, error) {
	execCtx, cancel := context.WithTimeout(ctx, s.rpmTimeout)
	defer cancel()

	var (
		diffCount int
		vaNote    string
		seen      = make(map[string]bool)
		paths     []string
	)
	err := s.run(execCtx, func(line []byte) bool {
		path := extractPath(line)
		if path == "" {
			return true
		}
		diffCount++
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
		return true
	}, "-Va")
	if err != nil {
		note, fatal := handleExecError(err)
		if fatal {
			return 0, "", err
		}
		vaNote = note
	}

	for _, path := range paths {
		qfCtx, qfCancel := context.WithTimeout(execCtx, s.rpmTimeout)
		var owners []string
		_ = s.run(qfCtx, func(line []byte) bool {
			owner := strings.TrimSpace(string(line))
			if owner != "" {
				owners = append(owners, owner)
			}
			return true
		}, "-qf", path, "--queryformat", nameQueryFormat)
		qfCancel()
		// multilib 同路径可能多 owner,全部纳入;无归属告警行(LC_ALL=C 下
		// stdout 上的 "file X is not owned by any package")必须排除。
		for _, owner := range owners {
			if isUnownedMessage(owner) {
				continue
			}
			out[owner] = struct{}{}
		}
	}
	return diffCount, vaNote, nil
}

// extractPath 从 rpm verify 一行输出中提取 path(missing 与 9 字节矩阵两路
// 都覆盖);解析失败返回 ""。
func extractPath(line []byte) string {
	s := strings.TrimRight(string(line), "\r\n")
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "missing ") {
		fields := strings.Fields(s)
		if len(fields) >= 2 {
			return fields[1]
		}
		return ""
	}
	// 9 字节 flag 矩阵行:flags[:9] + 空白 + type+ path
	if len(s) < 10 {
		return ""
	}
	rest := strings.TrimLeft(s[9:], " \t")
	// 类型标记(可能为 ' ', sp 内的归类)
	if len(rest) > 0 && strings.ContainsRune(typeMarkers, rune(rest[0])) {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	return rest
}

// pickTopN 从 pkg 集合里按字典序选前 n 个作为示例。
func pickTopN(set map[string]struct{}, n int) []string {
	all := make([]string, 0, len(set))
	for k := range set {
		all = append(all, k)
	}
	// 手写插入排序等价于 sort.SliceStable(all, func(i, j int) bool { return all[i] < all[j] }),
	// 仅作字典序排序,避免引入 sort 包。
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j-1] > all[j]; j-- {
			all[j-1], all[j] = all[j], all[j-1]
		}
	}
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

// --- 解析层 ---

// parseVerifyOutput 逐行解析 rpm -V 输出,返回好条目与坏行计数。坏行(行长度
// 不足或不是 missing/9 字节矩阵)跳过,整体不崩。
func parseVerifyOutput(lines [][]byte) ([]VerifyResult, int) {
	entries := make([]VerifyResult, 0, len(lines))
	skipped := 0
	for _, line := range lines {
		e, ok := parseVerifyLine(string(line))
		if !ok {
			skipped++
			continue
		}
		entries = append(entries, e)
	}
	return entries, skipped
}

// parseVerifyLine 解析一行 rpm -V 输出:`S.5....T.  c /etc/foo` 或
// `missing     /usr/libexec/foo (Permission denied)`。返回 ok=false 的行
// 整体被丢弃,调用方只增 skipped 计数。
func parseVerifyLine(s string) (VerifyResult, bool) {
	s = strings.TrimRight(s, "\r\n")
	if s == "" {
		return VerifyResult{}, false
	}

	// missing 文件缺失形态
	if strings.HasPrefix(s, "missing ") {
		fields := strings.Fields(s)
		if len(fields) < 2 {
			return VerifyResult{}, false
		}
		return VerifyResult{
			Path:  fields[1],
			Flags: VerifyFlags{Missing: true},
		}, true
	}

	// 9 字节 flag 矩阵 + 空白 + 类型标记 + 空白 + 路径
	if len(s) < 10 {
		return VerifyResult{}, false
	}
	flagBytes := s[:9]
	rest := s[9:]

	// 检查每字节是否在 {'.', flagChar, '?'};否则报非法
	for _, fb := range []byte(flagBytes) {
		if fb != '.' && fb != '?' && !strings.ContainsRune(verifyFlagChars, rune(fb)) {
			return VerifyResult{}, false
		}
	}

	flags := decodeFlags(flagBytes)

	// 跳过 1+ 空白
	rest = strings.TrimLeft(rest, " \t")
	if rest == "" {
		return VerifyResult{}, false
	}
	// 类型标记字符(可能为 ' ');若首字符在 cdlrg 集合中则取作 type
	typ := ""
	if len(rest) > 0 && strings.ContainsRune(typeMarkers, rune(rest[0])) {
		typ = string(rest[0])
		rest = rest[1:]
	}
	rest = strings.TrimLeft(rest, " \t")
	if rest == "" {
		return VerifyResult{}, false
	}

	return VerifyResult{
		Path:  rest,
		Type:  typ,
		Flags: flags,
	}, true
}

// decodeFlags 把 9 字节 flag 矩阵展开为 VerifyFlags。任何位为 '?' 视为
// Unreadable(rpm 无法读该属性,通常因 EACCES),但不影响其他位的解析;
// 按字符值而非位置识别差异位,兼容不同 rpm 版本可能的字段顺序差异。
func decodeFlags(flagBytes string) VerifyFlags {
	var f VerifyFlags
	for _, fb := range []byte(flagBytes) {
		if fb == '?' {
			f.Unreadable = true
			continue
		}
		if fb == '.' {
			continue
		}
		switch fb {
		case 'S':
			f.Size = true
		case 'M':
			f.Mode = true
		case '5':
			f.MD5 = true
		case 'D':
			f.Device = true
		case 'L':
			f.Symlink = true
		case 'U':
			f.User = true
		case 'G':
			f.Group = true
		case 'T':
			f.Mtime = true
		case 'P', 'C':
			f.Caps = true
		}
	}
	return f
}

// --- 进程层 ---

// runRPM 以绝对路径 argv 直发执行 rpm(绝不经过 sh -c),逐行把 stdout 回调
// 给 onLine。cmd.Stdin 置空(→ /dev/null);cmd.Env 注入 LC_ALL=C 锁定英文
// 输出(missing/unreadable 跨 i18n 一致解析)。onLine 返回 false 时杀子进
// 程并正常收工。
//
// 退出码语义(本函数为后续 CLI-fork 克隆的模板,纪律须钉死):
//   - ctx 超时/取消:优先返回 ctx.Err()(DeadlineExceeded / Canceled),不当作
//     真退出码处理。
//   - rc = 0:验证完成,正常返回 nil(调用方根据 stdout 内容判定"有/无差异")。
//   - rc = 1:包装为 *execError{Code:1,Stderr}。文档语义是"有差异 / 包未安装",
//     但本机实测 rpm 4.16.x 把所有正常退出都归 rc=0,rc=1 只见于 "X is not
//     installed" stderr 场景。两种含义由调用方按工具语义分流。
//   - rc ≥ 2:包装为 *execError{Code,Stderr} 上抛,典型是 rpm DB 损坏/不可
//     读的真故障,绝不吞。
func runRPM(ctx context.Context, onLine func([]byte) bool, args ...string) error {
	cmd := exec.CommandContext(ctx, rpmBinary, args...)
	cmd.Stdin = nil
	// LC_ALL=C 锁定英/中不一致的 missing / "权限不够" 注释为本地化代码,
	// 跨本进程允许 ≥ locale 解析。(拼 hint 也要写主程允许的固定串)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("rpm stdout 管道失败: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("rpm 启动失败: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	// rpm -Va 可能长达上万行,行长度可能很长(路径 1KB+),把行缓冲上限抬到
	// 16MiB 覆盖极端情况(与 journal 模板对齐)。
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		if !onLine(scanner.Bytes()) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil
		}
	}
	scanErr := scanner.Err()
	waitErr := cmd.Wait()

	// ctx 到期优先:让调用方 errors.Is 能区分 DeadlineExceeded/Canceled。
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if scanErr != nil {
		return fmt.Errorf("rpm 读取失败: %w", scanErr)
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			code := exitErr.ExitCode()
			if code != 0 {
				return &execError{
					Code:   code,
					Stderr: stderr.String(),
					Cause:  waitErr,
				}
			}
		}
		return fmt.Errorf("rpm 失败: %w(%s)", waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// --- 启动期环境探测 ---

// checkStartupEnv 在 daemon 启动期探测 rpm 二进制可用性与 euid;rpm 缺失或
// 非 root 时往 stderr 写一次性提示,工具调用时各自降级为 note(不崩)。
// 主调用方是 main()。
//
// 部署态在 DynamicUser 下 euid != 0 但具备 AmbientCapabilities=CAP_DAC_READ_SEARCH
// 时,代 valgrind 跳过 DAC 读检查可绕过 root-only 文件的 EACCES;此处仅告警
// "非 root + 无 cap" 双不满足的硬降级,具备 cap 的部署仍是合规态。
func checkStartupEnv() {
	if _, err := exec.LookPath(rpmBinary); err != nil {
		fmt.Fprintf(os.Stderr, "%s: rpm 二进制不可用 (%v);工具将返回空结果 + note\n", "daedalus-integrity", err)
		return
	}
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "%s: 非 root 运行;若未授予 CAP_DAC_READ_SEARCH,rpm -V 部分路径将因 EACCES 视为 missing,结果不完整\n", "daedalus-integrity")
	}
}
