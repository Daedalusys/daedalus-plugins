// Command daedalus-organize 是按规则文件整理能力 MCP 服务器(stdio JSON-RPC)。
//
// 提供 3 个工具:
//   - organize_plan(只读,无副作用):按 rule 分类 source_dir 下文件,产出
//     moves / conflicts 列表 + confirm_token(15 分钟过期,单次有效);
//   - organize_preview(只读,不消费 token):按 conflict_strategy 解析冲突,
//     给出最终 moves 与估算字节数;
//   - organize_apply(写型):校验 confirm_token,经 daedalus-tx 的 organize.move
//     适配器(begin→propose→apply)做事务性 os.Rename;写盘前经
//     pathguard.ValidateWritePath 二档校验,失败 fail-closed 拒执行。
//
// 写型工具的 confirm_token 来自 daedalus-sdk/confirmation 通用契约(plan
// "framework 缺口落地")。白名单启动时从 shared/policy.toml 读取并把
// [fs].allowed_dirs 注入 pathguard:缺失/损坏一律 fail-closed 拒启(回退
// Default 需 DAEDALUS_POLICY_MODE=development 显式 opt-in)。长扫描经 MCP
// notifications/progress 上报进度,不打印日志以免污染 JSON-RPC 数据流。
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/confirmation"
	"github.com/Daedalusys/daedalus-sdk/pathguard"
	"github.com/Daedalusys/daedalus-sdk/policy"
	"github.com/Daedalusys/daedalus-sdk/version"

	"github.com/Daedalusys/daedalus-plugins/organize/internal/classify"
)

const serverName = "daedalus-organize"

// txBinary 是 daedalus-tx CLI 的镜像安装路径(direct argv spawn, 不用 shell)。
const txBinary = "/usr/local/bin/daedalus-tx"

const (
	ruleByType = "by_type"
	ruleByDate = "by_date"
	ruleBySize = "by_size"
	ruleByExt  = "by_ext"

	strategyRename = "rename"
	strategySkip   = "skip"
	strategyAbort  = "abort"

	bucketSmall  = "<1MB"
	bucketMid    = "1-10MB"
	bucketLarge  = "10-100MB"
	bucketHuge   = ">100MB"

	progressStep = 50
)

// MCP go-sdk v1.8.0 的 ToolAnnotations.DestructiveHint / OpenWorldHint 字段
// 类型为 *bool,SDK 未导出取址助手,按实证形态声明包级哨兵变量后取址
// (直接写 plain false 字面量无法通过编译)。
var nonDestructive = false
var isDestructive = true
var closedWorld = false

type (
	// OrganizePlanInput 是 organize_plan 的入参(只读,会生成 confirm_token)。
	OrganizePlanInput struct {
		SourceDir string `json:"source_dir" jsonschema:"Absolute path of the directory to scan; must be within allowed directories."`
		Rule      string `json:"rule" jsonschema:"Classification rule: by_type, by_date, by_size, by_ext."`
	}
	// OrganizePreviewInput 是 organize_preview 的入参(只读,不消费 token)。
	OrganizePreviewInput struct {
		PlanID           string `json:"plan_id" jsonschema:"Plan ID returned by organize_plan."`
		ConflictStrategy string `json:"conflict_strategy" jsonschema:"rename, skip, or abort."`
	}
	// OrganizeApplyInput 是 organize_apply 的入参(写型,需 confirm_token + tx)。
	OrganizeApplyInput struct {
		PlanID           string `json:"plan_id" jsonschema:"Plan ID returned by organize_plan."`
		ConfirmToken     string `json:"confirm_token" jsonschema:"Single-use confirmation token issued by organize_plan."`
		ConflictStrategy string `json:"conflict_strategy" jsonschema:"rename, skip, or abort."`
	}
)

type moveEntry struct {
	From string `json:"from"`
	To   string `json:"to"`
	Size int64  `json:"size"`
	Rule string `json:"rule"`
}

type conflictEntry struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

type planResult struct {
	PlanID       string          `json:"plan_id"`
	ConfirmToken string          `json:"confirm_token"`
	Moves        []moveEntry     `json:"moves"`
	Conflicts    []conflictEntry `json:"conflicts"`
}

type previewFinalMove struct {
	From string `json:"from"`
	To   string `json:"to"`
	Size int64  `json:"size"`
}

type previewResult struct {
	Status              string            `json:"status"`
	Reason              string            `json:"reason,omitempty"`
	FinalMoves          []previewFinalMove `json:"final_moves,omitempty"`
	EstimatedTotalBytes int64             `json:"estimated_total_bytes,omitempty"`
}

type applyResult struct {
	TxID            string `json:"tx_id"`
	MovesApplied    int    `json:"moves_applied"`
	TotalMovedBytes int64  `json:"total_moved_bytes"`
}

// planStore 是 plan 阶段的内存仓库:RWMutex 保护 map,apply 阶段按 plan_id
// 取回 plan 并删除(preview 不消费,允许多次预览)。单进程内有效,跨进程无效
// (符合 in-memory 单次性约定,与 confirmation token 互补)。
type planStore struct {
	mu    sync.RWMutex
	plans map[string]*storedPlan
}

type storedPlan struct {
	SourceDir  string
	Rule       string
	Moves      []moveEntry
	Conflicts  []conflictEntry
	TargetMap  map[string]int // to → 出现次数(用于 plan 内去重)
	FinalMap   map[string]int // 上一轮 preview 的 final to(用于 preview 期间避免反复重算)
}

var plans = &planStore{plans: make(map[string]*storedPlan)}

func (s *planStore) put(id string, p *storedPlan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plans[id] = p
}

func (s *planStore) get(id string) (*storedPlan, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.plans[id]
	return p, ok
}

func (s *planStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.plans, id)
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

// applyPolicy 加载策略并把 [fs].allowed_dirs 注入 pathguard 包级白名单。
// organize 没有自己的 [write] 节,完全复用 fs 写白名单;policy.LoadOrDefault
// 缺失默认 fail-closed,仅 development opt-in 才回退 Default()。
func applyPolicy() error {
	p, err := policy.LoadOrDefault()
	if err != nil {
		return fmt.Errorf("policy load failed, refusing to start: %w", err)
	}
	allowed := append([]string{}, p.FS.AllowedDirs...)
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
		Name:        "organize_plan",
		Description: "Scan source_dir and produce a reorganization plan (moves + conflicts) plus a single-use confirm_token. Read-only; does not touch the filesystem beyond stat. rule: by_type, by_date, by_size, by_ext.",
		Annotations: readOnly,
	}, organizePlan)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "organize_preview",
		Description: "Resolve conflicts for an existing plan using the given strategy (rename/skip/abort). Read-only; confirm_token is NOT consumed.",
		Annotations: readOnly,
	}, organizePreview)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "organize_apply",
		Description: "Apply the plan after validating a single-use confirm_token. Rename is delegated to the daedalus-tx organize.move adapter (transactional begin→propose→apply→rollback). FAIL-CLOSED if pathguard.ValidateWritePath rejects any target.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: &isDestructive,
			IdempotentHint:  false,
			OpenWorldHint:   &closedWorld,
		},
	}, organizeApply)

	return server
}

// organizePlan 扫描 source_dir 并按 rule 分类,生成 plan + confirm_token。
// 不消费 token(token 仅在 apply 时消费),允许任意次 preview。
func organizePlan(ctx context.Context, req *mcp.CallToolRequest, in OrganizePlanInput) (*mcp.CallToolResult, any, error) {
	if in.SourceDir == "" {
		recordAudit("organize_plan", "denied", map[string]any{}, errors.New("source_dir required"))
		return toolError(errors.New("source_dir required")), nil, nil
	}
	if !isKnownRule(in.Rule) {
		recordAudit("organize_plan", "denied", map[string]any{"rule": in.Rule}, errors.New("unknown rule"))
		return toolError(fmt.Errorf("rule 必须为 by_type/by_date/by_size/by_ext 之一,实得 %q", in.Rule)), nil, nil
	}
	safe, err := pathguard.ValidatePath(in.SourceDir, false)
	if err != nil {
		recordAudit("organize_plan", "denied", map[string]any{"source_dir": in.SourceDir}, err)
		return toolError(err), nil, nil
	}

	moves, conflicts, err := scanForPlan(ctx, req, safe, in.Rule)
	if err != nil {
		recordAudit("organize_plan", "error", map[string]any{"source_dir": safe}, err)
		return nil, nil, err
	}

	planID := newPlanID()
	targetSet := make(map[string]int, len(moves))
	for _, m := range moves {
		targetSet[m.To]++
	}
	plans.put(planID, &storedPlan{
		SourceDir: safe,
		Rule:      in.Rule,
		Moves:     moves,
		Conflicts: conflicts,
		TargetMap: targetSet,
	})

	tok := confirmation.GenerateConfirmToken(planID)
	out := planResult{
		PlanID:       planID,
		ConfirmToken: tok.Token,
		Moves:        moves,
		Conflicts:    conflicts,
	}
	recordAudit("organize_plan", "success", map[string]any{"plan_id": planID, "moves": len(moves), "conflicts": len(conflicts)}, nil)
	return jsonResult(out), nil, nil
}

// organizePreview 解析冲突,生成 final_moves;不消费 token,plan 继续存在。
func organizePreview(_ context.Context, _ *mcp.CallToolRequest, in OrganizePreviewInput) (*mcp.CallToolResult, any, error) {
	if in.PlanID == "" {
		recordAudit("organize_preview", "denied", map[string]any{}, errors.New("plan_id required"))
		return toolError(errors.New("plan_id required")), nil, nil
	}
	if !isKnownStrategy(in.ConflictStrategy) {
		recordAudit("organize_preview", "denied", map[string]any{"plan_id": in.PlanID}, errors.New("unknown strategy"))
		return toolError(fmt.Errorf("conflict_strategy 必须为 rename/skip/abort 之一,实得 %q", in.ConflictStrategy)), nil, nil
	}
	plan, ok := plans.get(in.PlanID)
	if !ok {
		recordAudit("organize_preview", "denied", map[string]any{"plan_id": in.PlanID}, errors.New("plan not found"))
		return toolError(fmt.Errorf("plan_id %q 不存在或已过期", in.PlanID)), nil, nil
	}

	if in.ConflictStrategy == strategyAbort {
		out := previewResult{Status: "aborted", Reason: "conflict_strategy=abort 显式拒绝任何冲突"}
		recordAudit("organize_preview", "success", map[string]any{"plan_id": in.PlanID, "status": out.Status}, nil)
		return jsonResult(out), nil, nil
	}

	final := resolveConflicts(plan, in.ConflictStrategy)
	var total int64
	views := make([]previewFinalMove, 0, len(final))
	for _, m := range final {
		views = append(views, previewFinalMove{From: m.From, To: m.To, Size: m.Size})
		total += m.Size
	}
	plan.FinalMap = make(map[string]int, len(final))
	for _, m := range final {
		plan.FinalMap[m.To]++
	}
	out := previewResult{
		Status:              "ok",
		FinalMoves:          views,
		EstimatedTotalBytes: total,
	}
	recordAudit("organize_preview", "success", map[string]any{"plan_id": in.PlanID, "final_moves": len(views), "strategy": in.ConflictStrategy}, nil)
	return jsonResult(out), nil, nil
}

// organizeApply 三段流程:1) VerifyConfirmToken 校验并消费;2) 写二档校验
// 全部 from 路径;3) spawn daedalus-tx begin→propose→apply 直 argv 序列。
func organizeApply(ctx context.Context, _ *mcp.CallToolRequest, in OrganizeApplyInput) (*mcp.CallToolResult, any, error) {
	if in.PlanID == "" || in.ConfirmToken == "" {
		recordAudit("organize_apply", "denied", map[string]any{}, errors.New("plan_id and confirm_token required"))
		return toolError(errors.New("plan_id and confirm_token required")), nil, nil
	}
	if !isKnownStrategy(in.ConflictStrategy) {
		recordAudit("organize_apply", "denied", map[string]any{"plan_id": in.PlanID}, errors.New("unknown strategy"))
		return toolError(fmt.Errorf("conflict_strategy 必须为 rename/skip/abort 之一,实得 %q", in.ConflictStrategy)), nil, nil
	}

	// 1. confirm_token 校验(成功即消费)。
	tok := confirmation.ConfirmToken{Token: in.ConfirmToken, SubjectID: in.PlanID}
	if err := confirmation.VerifyConfirmToken(in.PlanID, tok); err != nil {
		recordAudit("organize_apply", "denied", map[string]any{"plan_id": in.PlanID}, err)
		return toolError(fmt.Errorf("confirm_token 校验失败: %w", err)), nil, nil
	}

	// plan 在 token 校验后再取:token 通过后 plan 必须仍存在(消费与读取在
	// 同一进程内,无并发竞争;但 plan_id 校验后才取,避免 token 失败时泄漏
	// plan 存在性)。
	plan, ok := plans.get(in.PlanID)
	if !ok {
		recordAudit("organize_apply", "error", map[string]any{"plan_id": in.PlanID}, errors.New("plan missing after token verify"))
		return toolError(fmt.Errorf("plan_id %q 不存在(可能在 confirm_token 校验前被清理)", in.PlanID)), nil, nil
	}
	plans.delete(in.PlanID)

	if in.ConflictStrategy == strategyAbort && len(plan.Conflicts) > 0 {
		recordAudit("organize_apply", "denied", map[string]any{"plan_id": in.PlanID, "conflicts": len(plan.Conflicts)}, errors.New("conflict_strategy=abort"))
		return toolError(fmt.Errorf("plan 含 %d 个冲突,conflict_strategy=abort 拒执行", len(plan.Conflicts))), nil, nil
	}

	final := resolveConflicts(plan, in.ConflictStrategy)
	if len(final) == 0 {
		out := applyResult{TxID: "", MovesApplied: 0, TotalMovedBytes: 0}
		recordAudit("organize_apply", "success", map[string]any{"plan_id": in.PlanID, "moves": 0}, nil)
		return jsonResult(out), nil, nil
	}

	// 2. 写二档校验:对每个 from 路径(已存在的源文件)走 pathguard.ValidateWritePath。
	// to 路径(目标)在 plan 阶段已保证落在 source_dir 子树下,source_dir 本身
	// 在白名单内;适配器侧仍会重校验 destination parent,实现纵深防御。
	fromPaths := make([]string, 0, len(final))
	for _, m := range final {
		if _, err := pathguard.ValidateWritePath(m.From); err != nil {
			recordAudit("organize_apply", "denied", map[string]any{"plan_id": in.PlanID, "from": m.From}, err)
			return toolError(fmt.Errorf("写二档拒绝 from %q: %w", m.From, err)), nil, nil
		}
		fromPaths = append(fromPaths, m.From)
	}

	// 3. spawn daedalus-tx 子命令序列。
	txID, totalBytes, err := runOrganizeMoveTx(ctx, in.PlanID, final)
	if err != nil {
		recordAudit("organize_apply", "error", map[string]any{"plan_id": in.PlanID, "tx_error": err.Error()}, err)
		return toolError(fmt.Errorf("daedalus-tx 提交失败: %w", err)), nil, nil
	}
	out := applyResult{TxID: txID, MovesApplied: len(final), TotalMovedBytes: totalBytes}
	recordAudit("organize_apply", "success", map[string]any{"plan_id": in.PlanID, "tx_id": txID, "moves": out.MovesApplied, "bytes": out.TotalMovedBytes}, nil)
	return jsonResult(out), nil, nil
}

// runOrganizeMoveTx 直 argv 序列化调用 daedalus-tx:begin → propose → apply。
// 无 shell 包装(sh -c / bash -c 被红线禁用);任一步失败立即返错。
func runOrganizeMoveTx(ctx context.Context, planID string, moves []moveEntry) (string, int64, error) {
	// args JSON 只携带必要字段(from/to/size/rule),不携带路径白名单信息
	// (适配器侧自行经 pathguard 重新校验)。
	type txMove struct {
		From string `json:"from"`
		To   string `json:"to"`
		Size int64  `json:"size_bytes"`
		Rule string `json:"rule"`
	}
	txMoves := make([]txMove, 0, len(moves))
	var totalBytes int64
	for _, m := range moves {
		txMoves = append(txMoves, txMove{From: m.From, To: m.To, Size: m.Size, Rule: m.Rule})
		totalBytes += m.Size
	}
	argsObj := map[string]any{
		"plan_id": planID,
		"moves":   txMoves,
	}
	args, err := json.Marshal(argsObj)
	if err != nil {
		return "", 0, fmt.Errorf("序列化 args 失败: %w", err)
	}

	begin := exec.CommandContext(ctx, txBinary, "begin", "--op", "organize.move")
	begin.Stderr = os.Stderr
	beginOut, err := begin.Output()
	if err != nil {
		return "", 0, fmt.Errorf("begin 失败: %w", err)
	}
	txID := strings.TrimSpace(string(beginOut))
	if txID == "" {
		return "", 0, errors.New("begin 未返回 tx_id")
	}

	propose := exec.CommandContext(ctx, txBinary, "propose", "--tx", txID, "--op", "organize.move", "--args", string(args))
	propose.Stderr = os.Stderr
	if err := propose.Run(); err != nil {
		return "", 0, fmt.Errorf("propose 失败: %w", err)
	}

	apply := exec.CommandContext(ctx, txBinary, "apply", "--tx", txID)
	apply.Stderr = os.Stderr
	if err := apply.Run(); err != nil {
		return "", 0, fmt.Errorf("apply 失败: %w", err)
	}
	return txID, totalBytes, nil
}

// scanForPlan 是 organize_plan 阶段的扫描与分类核心:栈式深搜,跳过符号链接,
// 按 rule 决定每个文件的 dest dir。冲突分两类:dest 真实已存在(磁盘冲突)
// 与 dest 在本 plan 内被多次命中(plan 内冲突)。
func scanForPlan(ctx context.Context, req *mcp.CallToolRequest, root, rule string) ([]moveEntry, []conflictEntry, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, nil, fmt.Errorf("readdir %s: %w", root, err)
	}
	moves := make([]moveEntry, 0)
	conflicts := make([]conflictEntry, 0)
	targetCount := make(map[string]int)
	processed := 0
	for _, e := range entries {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}
		full := filepath.Join(root, e.Name())
		info, err := os.Lstat(full)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		processed++
		if processed%progressStep == 0 {
			reportProgress(ctx, req, "organize-plan", processed)
		}
		dir, err := dirForRule(full, info, rule)
		if err != nil {
			conflicts = append(conflicts, conflictEntry{From: full, To: "", Reason: err.Error()})
			continue
		}
		to := filepath.Join(root, dir, e.Name())
		entry := moveEntry{From: full, To: to, Size: info.Size(), Rule: rule}
		moves = append(moves, entry)
		targetCount[to]++
		if _, err := os.Stat(to); err == nil {
			conflicts = append(conflicts, conflictEntry{
				From:   full,
				To:     to,
				Reason: "目标文件已存在",
			})
		}
	}
	for _, m := range moves {
		if targetCount[m.To] > 1 {
			conflicts = append(conflicts, conflictEntry{
				From:   m.From,
				To:     m.To,
				Reason: fmt.Sprintf("目标被 plan 内 %d 个文件命中", targetCount[m.To]),
			})
		}
	}
	return moves, conflicts, nil
}

// dirForRule 把单文件按 rule 映射到目标子目录名(相对 source_dir)。
func dirForRule(path string, info os.FileInfo, rule string) (string, error) {
	switch rule {
	case ruleByType:
		cat, err := classify.Type(path)
		if err != nil {
			return "", err
		}
		return cat, nil
	case ruleByDate:
		mtime := info.ModTime().UTC()
		return fmt.Sprintf("%d/%d-%02d", mtime.Year(), mtime.Year(), int(mtime.Month())), nil
	case ruleBySize:
		return sizeBucket(info.Size()), nil
	case ruleByExt:
		ext := strings.TrimPrefix(filepath.Ext(path), ".")
		if ext == "" {
			return "other", nil
		}
		return strings.ToLower(ext), nil
	}
	return "", fmt.Errorf("未知 rule: %q", rule)
}

// sizeBucket 把字节数落桶:四个固定桶,边界含下界不含上界,>100MB 兜底。
func sizeBucket(n int64) string {
	const (
		mb1  = int64(1) << 20
		mb10 = int64(10) << 20
		mb100 = int64(100) << 20
	)
	switch {
	case n < mb1:
		return bucketSmall
	case n < mb10:
		return bucketMid
	case n < mb100:
		return bucketLarge
	default:
		return bucketHuge
	}
}

// resolveConflicts 按 strategy 处理冲突:rename 追加 " (1)" " (2)" 后缀,
// skip 移除冲突项;abort 调用方在 preview/apply 阶段已先 return。
func resolveConflicts(plan *storedPlan, strategy string) []moveEntry {
	if len(plan.Conflicts) == 0 {
		return append([]moveEntry{}, plan.Moves...)
	}
	conflicted := make(map[string]bool)
	diskConflicts := make(map[string]bool)
	for _, c := range plan.Conflicts {
		if c.To == "" {
			continue
		}
		conflicted[c.From] = true
		diskConflicts[c.To] = true
	}
	out := make([]moveEntry, 0, len(plan.Moves))
	usedTo := make(map[string]struct{})
	for _, m := range plan.Moves {
		if strategy == strategySkip && conflicted[m.From] {
			continue
		}
		to := m.To
		if strategy == strategyRename && diskConflicts[m.To] {
			to = uniquePath(m.To, usedTo)
		}
		out = append(out, moveEntry{From: m.From, To: to, Size: m.Size, Rule: m.Rule})
		usedTo[to] = struct{}{}
	}
	return out
}

// uniquePath 在 to 已被占用时生成 " (1)" / " (2)" ... 后缀的新路径。
// usedTo 是本次 final 列表内已分配的 to 集合,避免重名落盘。
func uniquePath(to string, usedTo map[string]struct{}) string {
	dir := filepath.Dir(to)
	base := filepath.Base(to)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	for i := 1; ; i++ {
		candidate := filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
		if _, used := usedTo[candidate]; used {
			continue
		}
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
	}
}

// newPlanID 生成 16-hex 字符的 plan_id(与 tx-id 同形态,方便消费方复用
// 同一形状校验);crypto/rand 出错时回退到时间戳拼纳秒。
func newPlanID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return "organize-" + hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("organize-%d", time.Now().UnixNano())
}

func isKnownRule(r string) bool {
	switch r {
	case ruleByType, ruleByDate, ruleBySize, ruleByExt:
		return true
	}
	return false
}

func isKnownStrategy(s string) bool {
	switch s {
	case strategyRename, strategySkip, strategyAbort:
		return true
	}
	return false
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
