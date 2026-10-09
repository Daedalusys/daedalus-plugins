// Command daedalus-diskclean 是磁盘清理能力 MCP 服务器(stdio JSON-RPC)。
//
// 提供 4 个工具:
//   - disk_scan(只读):按 category 过滤扫描候选可清理项,返回每条估算大小与风险标签;
//   - disk_estimate(只读):对选中项汇总,不消费 confirm_token;
//   - disk_explain(只读):解释某目录为何存在 / 删了会怎样;
//   - disk_clean(写型):必须配对 confirm_token,走 daedalus-tx 的 disk.clean
//     适配器(事务通道 begin→propose→apply→rollback);写盘前经
//     pathguard.ValidateWritePath 二档校验,失败 fail-closed 拒执行。
//
// 写型工具的 confirm_token 来自 daedalus-sdk/confirmation 通用契约(plan
// "framework 缺口落地")。白名单启动时从 shared/policy.toml 读取并合并
// [fs].allowed_dirs + [diskclean].allowed_write_dirs 注入 pathguard:缺失/损坏
// 一律 fail-closed 拒启(回退 Default 需 DAEDALUS_POLICY_MODE=development 显式
// opt-in)。长扫描经 MCP notifications/progress 上报进度,不打印日志以免污染
// JSON-RPC 数据流。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/confirmation"
	"github.com/Daedalusys/daedalus-sdk/pathguard"
	"github.com/Daedalusys/daedalus-sdk/policy"
	"github.com/Daedalusys/daedalus-sdk/version"
)

const serverName = "daedalus-diskclean"

// category 标签全集;写型工具的 risk 分级由 riskForCategory 决定。
const (
	categoryJournal    = "journal"
	categoryDNFCache   = "dnf_cache"
	categoryPackageKit = "packagekit_cache"
	categoryCoredump   = "coredump"
	categoryOldKernel  = "old_kernel"
	categoryUserCache  = "user_cache"
	categoryTmpOld     = "tmp_old"

	riskSafe    = "safe"
	riskCaution = "caution"
	riskRisky   = "risky"

	defaultMinSizeBytes int64 = 0
	defaultTopN         int   = 20
	progressStep        int   = 50

	// txBinary 是 daedalus-tx CLI 的镜像安装路径(direct argv spawn,不用 shell)。
	txBinary = "/usr/local/bin/daedalus-tx"
)

// MCP go-sdk v1.8.0 的 ToolAnnotations.DestructiveHint / OpenWorldHint 字段
// 类型为 *bool,且 SDK 未导出取址助手,故按实证形态声明包级哨兵变量后取址
// (直接写 plain false 字面量无法通过编译)。
var nonDestructive = false
var isDestructive = true
var closedWorld = false

type (
	// DiskScanInput 是 disk_scan 的入参。
	DiskScanInput struct {
		Paths      []string `json:"paths" jsonschema:"Absolute paths within allowed directories to scan."`
		MinSize    int64    `json:"min_size,omitempty" jsonschema:"Minimum size in bytes to report; defaults to 0."`
		TopN       int      `json:"top_n,omitempty" jsonschema:"Maximum entries per category; defaults to 20."`
		Categories []string `json:"categories,omitempty" jsonschema:"Filter categories: journal, dnf_cache, packagekit_cache, coredump, old_kernel, user_cache, tmp_old. Empty = all."`
	}
	// DiskEstimateInput 是 disk_estimate 的入参(只读,不发 token)。
	DiskEstimateInput struct {
		Paths []string `json:"paths" jsonschema:"Paths to estimate; must be within allowed directories."`
	}
	// DiskExplainInput 是 disk_explain 的入参。
	DiskExplainInput struct {
		Path string `json:"path" jsonschema:"Absolute path within allowed directories to explain."`
	}
	// DiskCleanInput 是 disk_clean 的入参(写型,需 confirm_token + tx)。
	DiskCleanInput struct {
		PlanID       string   `json:"plan_id" jsonschema:"Plan ID from the scan/estimate phase."`
		ConfirmToken string   `json:"confirm_token" jsonschema:"Single-use confirmation token."`
		Paths        []string `json:"paths" jsonschema:"Paths to clean; each must pass pathguard.ValidateWritePath."`
	}
)

type cleanItem struct {
	Path     string `json:"path"`
	Category string `json:"category"`
	Size     int64  `json:"size_bytes"`
	MTime    string `json:"mtime,omitempty"`
	Risk     string `json:"risk"`
	Reason   string `json:"reason"`
}

type scanResult struct {
	Items      []cleanItem `json:"items"`
	TotalBytes int64       `json:"total_bytes"`
	Categories []string    `json:"categories_scanned"`
}

type estimateResult struct {
	Items      []cleanItem `json:"items"`
	TotalBytes int64       `json:"total_bytes"`
}

type explainResult struct {
	Path          string `json:"path"`
	Category      string `json:"category"`
	What          string `json:"what"`
	RiskReason    string `json:"risk_reason"`
	WhatIfDeleted string `json:"what_if_deleted"`
}

type cleanResult struct {
	TxID         string `json:"tx_id"`
	ItemsCleaned int    `json:"items_cleaned"`
	TotalBytes   int64  `json:"total_bytes_cleaned"`
	RollbackOK   bool   `json:"rollback_on_error"`
}

func main() {
	if err := applyPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}
	server := newServer()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !isCleanShutdown(err) {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}
}

// applyPolicy 加载策略并把 [fs].allowed_dirs ∪ [diskclean].allowed_write_dirs
// 注入 pathguard 包级白名单。policy.LoadOrDefault 缺失默认 fail-closed,仅
// development opt-in 才回退 Default()。
func applyPolicy() error {
	p, err := policy.LoadOrDefault()
	if err != nil {
		return fmt.Errorf("policy load failed, refusing to start: %w", err)
	}
	allowed := append([]string{}, p.FS.AllowedDirs...)
	allowed = append(allowed, p.DiskClean.AllowedWriteDirs...)
	pathguard.WithAllowedDirs(allowed)
	policyAuditLogPath = p.Audit.LogPath
	return nil
}

func isCleanShutdown(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return true
	}
	return strings.HasPrefix(err.Error(), "server is closing")
}

func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	readOnly := &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "disk_scan",
		Description: "Scan candidate cleanable items (journal / dnf cache / packagekit / coredump / old kernel / user cache / tmp old) within allowed directories. Returns per-item size + risk label (safe/caution/risky). Read-only.",
		Annotations: readOnly,
	}, diskScan)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "disk_estimate",
		Description: "Estimate total size for the given paths within allowed directories. Read-only; does NOT generate a confirm_token.",
		Annotations: readOnly,
	}, diskEstimate)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "disk_explain",
		Description: "Explain why a path exists, its category, and what would happen if deleted. Read-only.",
		Annotations: readOnly,
	}, diskExplain)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "disk_clean",
		Description: "Delete the given paths after validating a single-use confirm_token from the plan phase. Deletion is delegated to the daedalus-tx disk.clean adapter (transactional begin→propose→apply→rollback). FAIL-CLOSED if pathguard.ValidateWritePath rejects any target.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: &isDestructive,
			IdempotentHint:  false,
			OpenWorldHint:   &closedWorld,
		},
	}, diskClean)

	return server
}

// diskScan 只读扫描:每个 path 走 pathguard.ValidatePath 读档校验,walker 分类
// 收集,按 size 降序、每 category 取 topN;每 progressStep 个文件上报 progress。
func diskScan(ctx context.Context, req *mcp.CallToolRequest, in DiskScanInput) (*mcp.CallToolResult, any, error) {
	if len(in.Paths) == 0 {
		recordAudit("disk_scan", "denied", map[string]any{}, errors.New("empty paths"))
		return toolError(errors.New("paths must contain at least one directory")), nil, nil
	}
	topN := in.TopN
	if topN <= 0 {
		topN = defaultTopN
	}
	allowed := normalizeCategories(in.Categories)
	items := make([]cleanItem, 0)
	cats := make(map[string]struct{})
	for _, p := range in.Paths {
		safe, err := pathguard.ValidatePath(p, false)
		if err != nil {
			recordAudit("disk_scan", "denied", map[string]any{"path": p}, err)
			return toolError(err), nil, nil
		}
		walked, err := walkForCleanup(ctx, safe, in.MinSize, topN, allowed, func(n int) {
			reportProgress(ctx, req, "disk-scan", n)
		})
		if err != nil {
			recordAudit("disk_scan", "error", map[string]any{"path": p}, err)
			return nil, nil, err
		}
		for _, it := range walked {
			cats[it.Category] = struct{}{}
		}
		items = append(items, walked...)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Size > items[j].Size })
	categoryList := make([]string, 0, len(cats))
	for c := range cats {
		categoryList = append(categoryList, c)
	}
	sort.Strings(categoryList)
	out := scanResult{Items: items, TotalBytes: totalSize(items), Categories: categoryList}
	recordAudit("disk_scan", "success", map[string]any{"items": len(items), "total_bytes": out.TotalBytes}, nil)
	return jsonResult(out), nil, nil
}

// diskEstimate 只读汇总,不消费 token,不生成新 token。
func diskEstimate(ctx context.Context, _ *mcp.CallToolRequest, in DiskEstimateInput) (*mcp.CallToolResult, any, error) {
	if len(in.Paths) == 0 {
		recordAudit("disk_estimate", "denied", map[string]any{}, errors.New("empty paths"))
		return toolError(errors.New("paths must contain at least one directory")), nil, nil
	}
	items := make([]cleanItem, 0)
	for _, p := range in.Paths {
		safe, err := pathguard.ValidatePath(p, false)
		if err != nil {
			recordAudit("disk_estimate", "denied", map[string]any{"path": p}, err)
			return toolError(err), nil, nil
		}
		walked, err := walkForCleanup(ctx, safe, defaultMinSizeBytes, defaultTopN, nil, nil)
		if err != nil {
			recordAudit("disk_estimate", "error", map[string]any{"path": p}, err)
			return nil, nil, err
		}
		items = append(items, walked...)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Size > items[j].Size })
	out := estimateResult{Items: items, TotalBytes: totalSize(items)}
	recordAudit("disk_estimate", "success", map[string]any{"items": len(items), "total_bytes": out.TotalBytes}, nil)
	return jsonResult(out), nil, nil
}

// diskExplain 返回某路径的 category 与解释文本(硬编码分类 → 解释字符串)。
func diskExplain(ctx context.Context, _ *mcp.CallToolRequest, in DiskExplainInput) (*mcp.CallToolResult, any, error) {
	if in.Path == "" {
		recordAudit("disk_explain", "denied", map[string]any{}, errors.New("empty path"))
		return toolError(errors.New("path required")), nil, nil
	}
	safe, err := pathguard.ValidatePath(in.Path, false)
	if err != nil {
		recordAudit("disk_explain", "denied", map[string]any{"path": in.Path}, err)
		return toolError(err), nil, nil
	}
	category := classifyPath(safe)
	out := explainResult{
		Path:          safe,
		Category:      category,
		What:          whatForCategory(category, safe),
		RiskReason:    riskReasonForCategory(category),
		WhatIfDeleted: whatIfDeletedForCategory(category),
	}
	recordAudit("disk_explain", "success", map[string]any{"path": safe, "category": category}, nil)
	_ = ctx
	return jsonResult(out), nil, nil
}

// diskClean 写型工具三段流程:
//  1. confirmation.VerifyConfirmToken 校验并消费 token(单次有效);
//  2. 每个 path 走 pathguard.ValidateWritePath 二档校验(拒写只读系统目录 +
//     敏感文件 + 强制完整 realpath);
//  3. spawn /usr/local/bin/daedalus-tx 子命令序列 begin→propose→apply(直 argv,
//     不经 sh -c),捕获 tx_id 返回。
func diskClean(ctx context.Context, _ *mcp.CallToolRequest, in DiskCleanInput) (*mcp.CallToolResult, any, error) {
	if in.PlanID == "" || in.ConfirmToken == "" {
		recordAudit("disk_clean", "denied", map[string]any{}, errors.New("plan_id and confirm_token required"))
		return toolError(errors.New("plan_id and confirm_token required")), nil, nil
	}
	if len(in.Paths) == 0 {
		recordAudit("disk_clean", "denied", map[string]any{"plan_id": in.PlanID}, errors.New("paths required"))
		return toolError(errors.New("paths must contain at least one directory")), nil, nil
	}

	// 1. confirm_token 校验(成功即消费)。
	tok := confirmation.ConfirmToken{Token: in.ConfirmToken, SubjectID: in.PlanID}
	if err := confirmation.VerifyConfirmToken(in.PlanID, tok); err != nil {
		recordAudit("disk_clean", "denied", map[string]any{"plan_id": in.PlanID}, err)
		return toolError(fmt.Errorf("confirm_token 校验失败: %w", err)), nil, nil
	}

	// 2. 写二档校验。
	cleanPaths := make([]string, 0, len(in.Paths))
	for _, p := range in.Paths {
		safe, err := pathguard.ValidateWritePath(p)
		if err != nil {
			recordAudit("disk_clean", "denied", map[string]any{"plan_id": in.PlanID, "path": p}, err)
			return toolError(fmt.Errorf("写二档拒绝 %q: %w", p, err)), nil, nil
		}
		cleanPaths = append(cleanPaths, safe)
	}

	// 3. daedalus-tx 子命令序列。
	txID, err := runDiskCleanTx(ctx, in.PlanID, cleanPaths)
	if err != nil {
		recordAudit("disk_clean", "error", map[string]any{"plan_id": in.PlanID, "tx_error": err.Error()}, err)
		return toolError(fmt.Errorf("daedalus-tx 提交失败: %w", err)), nil, nil
	}

	out := cleanResult{TxID: txID, ItemsCleaned: len(cleanPaths), RollbackOK: true}
	recordAudit("disk_clean", "success", map[string]any{"plan_id": in.PlanID, "tx_id": txID, "items": out.ItemsCleaned}, nil)
	return jsonResult(out), nil, nil
}

// runDiskCleanTx 直 argv 序列化调用 daedalus-tx:begin → propose → apply。
// 无 shell 包装(sh -c / bash -c 被红线禁用);任一步失败立即返错。
func runDiskCleanTx(ctx context.Context, planID string, paths []string) (string, error) {
	args, err := json.Marshal(map[string]any{"paths": paths, "plan_id": planID})
	if err != nil {
		return "", fmt.Errorf("序列化 args 失败: %w", err)
	}

	begin := exec.CommandContext(ctx, txBinary, "begin", "--op", "disk.clean")
	begin.Stderr = os.Stderr
	beginOut, err := begin.Output()
	if err != nil {
		return "", fmt.Errorf("begin 失败: %w", err)
	}
	txID := strings.TrimSpace(string(beginOut))
	if txID == "" {
		return "", errors.New("begin 未返回 tx_id")
	}

	propose := exec.CommandContext(ctx, txBinary, "propose", "--tx", txID, "--op", "disk.clean", "--args", string(args))
	propose.Stderr = os.Stderr
	if err := propose.Run(); err != nil {
		return "", fmt.Errorf("propose 失败: %w", err)
	}

	apply := exec.CommandContext(ctx, txBinary, "apply", "--tx", txID)
	apply.Stderr = os.Stderr
	if err := apply.Run(); err != nil {
		return "", fmt.Errorf("apply 失败: %w", err)
	}
	return txID, nil
}

// walkForCleanup 是 disk-scan / disk-estimate 共用 walker:栈式深搜,不跟随
// 符号链接,跳过非常规文件;按 category(路径前缀)分类收集;每个类别内按 size
// 降序取 topN 后合并。每 progressStep 个文件回调 progress。
func walkForCleanup(ctx context.Context, root string, minSize int64, topN int, allowedCats map[string]bool, progress func(int)) ([]cleanItem, error) {
	rootCategory := classifyPath(root)
	if allowedCats != nil && !allowedCats[rootCategory] {
		return nil, nil
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil
	}

	perCategory := make(map[string][]cleanItem)
	scanned := 0
	stack := []string{root}
	for len(stack) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			p := filepath.Join(dir, e.Name())
			fi, err := os.Lstat(p)
			if err != nil || fi.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if fi.IsDir() {
				stack = append(stack, p)
				continue
			}
			if !fi.Mode().IsRegular() || fi.Size() < minSize {
				continue
			}
			scanned++
			if progress != nil && scanned%progressStep == 0 {
				progress(scanned)
			}
			cat := classifyPath(p)
			if allowedCats != nil && !allowedCats[cat] {
				continue
			}
			perCategory[cat] = append(perCategory[cat], cleanItem{
				Path:     p,
				Category: cat,
				Size:     fi.Size(),
				MTime:    fi.ModTime().UTC().Format(time.RFC3339),
				Risk:     riskForCategory(cat),
				Reason:   reasonForCategory(cat),
			})
		}
	}

	flat := make([]cleanItem, 0)
	for _, bucket := range perCategory {
		sort.SliceStable(bucket, func(i, j int) bool { return bucket[i].Size > bucket[j].Size })
		if topN > 0 && len(bucket) > topN {
			bucket = bucket[:topN]
		}
		flat = append(flat, bucket...)
	}
	sort.SliceStable(flat, func(i, j int) bool { return flat[i].Size > flat[j].Size })
	return flat, nil
}

// classifyPath 按路径前缀分桶到 category;不在任何白名单前缀则归 user_cache 兜底。
func classifyPath(p string) string {
	switch {
	case strings.HasPrefix(p, "/var/log/journal"):
		return categoryJournal
	case strings.HasPrefix(p, "/var/cache/dnf"):
		return categoryDNFCache
	case strings.HasPrefix(p, "/var/cache/PackageKit"):
		return categoryPackageKit
	case strings.HasPrefix(p, "/var/lib/systemd/coredump"):
		return categoryCoredump
	case strings.HasPrefix(p, "/var/tmp"):
		return categoryTmpOld
	case strings.HasPrefix(p, "/var/log"):
		return categoryJournal
	case strings.HasPrefix(p, "/boot"):
		return categoryOldKernel
	case strings.HasPrefix(p, "/home"):
		return categoryUserCache
	default:
		return categoryUserCache
	}
}

func normalizeCategories(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for _, c := range in {
		out[c] = true
	}
	return out
}

func riskForCategory(cat string) string {
	switch cat {
	case categoryJournal, categoryTmpOld:
		return riskSafe
	case categoryDNFCache, categoryPackageKit, categoryUserCache:
		return riskCaution
	case categoryCoredump, categoryOldKernel:
		return riskRisky
	}
	return riskCaution
}

func reasonForCategory(cat string) string {
	switch cat {
	case categoryJournal:
		return "systemd 日志,可由 journalctl 自动 vacuum 重建"
	case categoryDNFCache:
		return "dnf 缓存,重装时由 dnf 自动重建"
	case categoryPackageKit:
		return "PackageKit 缓存,可由 dnf clean metadata 重建"
	case categoryCoredump:
		return "coredump,删除后无法再用 crash 分析"
	case categoryTmpOld:
		return "/var/tmp 下保留期临时文件"
	case categoryOldKernel:
		return "旧内核,通过 rpm -q kernel 比对启动项识别"
	case categoryUserCache:
		return "用户态 ~/.cache,应用按需重建"
	}
	return ""
}

func whatForCategory(cat, p string) string {
	switch cat {
	case categoryJournal:
		return fmt.Sprintf("%s 是 systemd-journald 持久化日志目录", p)
	case categoryDNFCache:
		return fmt.Sprintf("%s 是 dnf 下载的软件包/元数据缓存", p)
	case categoryPackageKit:
		return fmt.Sprintf("%s 是 PackageKit 的事务缓存", p)
	case categoryCoredump:
		return fmt.Sprintf("%s 是 systemd-coredump 写入的崩溃转储", p)
	case categoryTmpOld:
		return fmt.Sprintf("%s 是 /var/tmp 下保留期临时文件", p)
	case categoryOldKernel:
		return fmt.Sprintf("%s 是 rpm -q kernel 解析到的旧内核目录", p)
	case categoryUserCache:
		return fmt.Sprintf("%s 是用户态 ~/.cache 缓存", p)
	}
	return ""
}

func riskReasonForCategory(cat string) string {
	switch cat {
	case categoryJournal:
		return "影响:日志丢失;恢复:journald 自动 vacuum 重建"
	case categoryDNFCache:
		return "影响:下次 dnf install 重新下载包;恢复:dnf 自动重建"
	case categoryPackageKit:
		return "影响:PackageKit 重新生成元数据;恢复:dnf clean metadata"
	case categoryCoredump:
		return "影响:无法再用 crash 工具分析该次崩溃;不可恢复"
	case categoryTmpOld:
		return "影响:进程未关闭的 fd 引用会泄漏;恢复:用户进程重连"
	case categoryOldKernel:
		return "影响:回滚到该内核版本不可用;恢复:从 bootc 镜像重装"
	case categoryUserCache:
		return "影响:应用首次启动变慢(重建);恢复:应用自行重建"
	}
	return ""
}

func whatIfDeletedForCategory(cat string) string {
	switch cat {
	case categoryJournal:
		return "释放磁盘空间;journald 后续记录继续写入;旧日志无法回看"
	case categoryDNFCache:
		return "下次 dnf install / upgrade 需重新下载受影响包"
	case categoryPackageKit:
		return "下次 PackageKit 操作重新拉取元数据"
	case categoryCoredump:
		return "崩溃诊断数据永久丢失;运行中服务不受影响"
	case categoryTmpOld:
		return "未引用的临时文件被清;运行进程 fd 仍指向 inode"
	case categoryOldKernel:
		return "boot loader 条目不变;仅物理文件删除,需 bootc 重建"
	case categoryUserCache:
		return "应用首次启动时重建缓存;运行实例通常不受影响"
	}
	return ""
}

func totalSize(items []cleanItem) int64 {
	var t int64
	for _, it := range items {
		t += it.Size
	}
	return t
}

// reportProgress 经 MCP 协议级 notifications/progress 上报处理进度;req 或
// req.Session 为 nil(直接单测调用)时静默跳过。
func reportProgress(ctx context.Context, req *mcp.CallToolRequest, token string, n int) {
	if req == nil || req.Session == nil {
		return
	}
	_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
		ProgressToken: token,
		Progress:      float64(n),
	})
}

func jsonResult(v any) *mcp.CallToolResult {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError(err)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}
}

func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "Error: " + err.Error()}},
		IsError: true,
	}
}
