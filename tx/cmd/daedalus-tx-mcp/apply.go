// apply.go —— tx_apply 的主流程:判定 → 三档分派 → 执行 / 出待办 → 审计。
//
// 判定本身是纯函数(preview.go 的 buildPreview);本文件只回答"拿到判定后做什么":
// auto 直接走事务,confirm 先消费条子(记账与判定在同一把进程内锁下),human 只出
// 待办,等人写好批准记录再来一次才执行。所有拒绝都以机器可读码返回:客户端按码
// 分支,人看 reason 与 detail。
package main

import (
	"fmt"
	"time"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
)

const (
	// toolApply 是本工具在审计链里的名字(与 manifest.tools 逐字一致)。
	toolApply = "tx_apply"
	// pendingTTL 是待办的有效期:过期未批准即作废,AI 需重新申请。
	pendingTTL = time.Hour
)

// 拒绝码。每个码对应一个独立的失败前提 —— 混成一个 "denied" 会让客户端与运维
// 都失去"到底缺什么"的信息。
const (
	codeGrantRequired      = "grant_required"
	codeGrantRevoked       = "grant_revoked"
	codeGrantInvalid       = "grant_invalid"
	codeGrantUnauthorized  = "grant_unauthorized"
	codeGrantExpired       = "grant_expired"
	codeGrantScopeMismatch = "grant_scope_mismatch"
	codeGrantExhausted     = "grant_exhausted"
	codeGrantUsageFailed   = "grant_usage_failed"
	codeApprovalRequired   = "human_approval_required"
	codeApprovalUntrusted  = "approval_untrusted"
	codeApprovalMismatch   = "approval_mismatch"
	codeApprovalStale      = "approval_stale"
	codePendingWriteFailed = "pending_write_failed"
	codeTxFailed           = "tx_failed"
)

// applyIn 是 tx_apply 的入参。GrantID 只在第二档有意义;Actor 是客户端自报身份,
// 只作审计线索,绝不参与任何判据。
type applyIn struct {
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	DesiredState string `json:"desired_state"`
	GrantID      string `json:"grant_id"`
	Actor        string `json:"actor"`
}

// applyView 是执行成功(含幂等)时的应答。
type applyView struct {
	TxID       string   `json:"tx_id,omitempty"`
	Tier       string   `json:"tier"`
	Outcome    string   `json:"outcome"`
	GrantID    string   `json:"grant_id,omitempty"`
	PendingID  string   `json:"pending_id,omitempty"`
	Argv       []string `json:"argv,omitempty"`
	Scope      string   `json:"scope"`
	Reason     string   `json:"reason,omitempty"`
	ApprovedBy string   `json:"approved_by,omitempty"`
}

// applyRejection 是拒绝面:error 是机器可读码,tier/required_scope 让客户端知道
// 下一步该做什么,reason/detail 给人看。第三档的拒绝还带 pending_id 与 argv。
type applyRejection struct {
	Error         string   `json:"error"`
	Tier          string   `json:"tier,omitempty"`
	RequiredScope []string `json:"required_scope,omitempty"`
	PendingID     string   `json:"pending_id,omitempty"`
	Argv          []string `json:"argv,omitempty"`
	// ArgvSHA256 是待批准 argv 的指纹:人把它抄给 daedalus-tx approve --expect-sha256,
	// 批准才绑定在自己看过的那一条命令上。
	ArgvSHA256 string `json:"argv_sha256,omitempty"`
	Reason     string `json:"reason"`
	Detail     string `json:"detail,omitempty"`
}

// txApply 是一次受控变更的完整判定与执行。审计在这里统一写:不论执行、幂等、
// 拒绝还是失败,都必须留下一条带 tier 的证据。
func txApply(cfg *autonomy.Config, in applyIn) (applyView, *applyRejection) {
	args := baseAuditArgs(in)

	unit, serr := preparePreview(previewIn{Kind: in.Kind, Name: in.Name, DesiredState: in.DesiredState})
	if serr != nil {
		rej := &applyRejection{Error: serr.Error, Reason: serr.Detail}
		args["error"] = serr.Error
		recordAudit(toolApply, "denied", args, nil)
		return applyView{}, rej
	}

	// 属性在每次 apply 时重新观测:签发时的判定结果不算数。
	obs := observeUnit(unit)
	view, serr := buildPreview(in.DesiredState, unit, domainUser, cfg, obs)
	if serr != nil {
		rej := &applyRejection{Error: serr.Error, Reason: serr.Detail}
		args["error"] = serr.Error
		recordAudit(toolApply, "denied", args, nil)
		return applyView{}, rej
	}
	args["tier"] = view.Tier
	args["scope"] = view.Scope
	args["decision_path"] = []string{view.Reason}

	// 事务的两键必须与"将被批准的 argv"同源:从这里往下,单元名与期望状态
	// 一律取 argv 反解出来的值,不再抄请求里的字面量 —— 否则改了动词表,
	// 批准的是一条命令、执行的却是另一个动作。
	intent, ok := serviceSetIntentFromArgv(view.Argv)
	if !ok {
		args["error"] = codeTxFailed
		recordAudit(toolApply, "denied", args, nil)
		return applyView{}, &applyRejection{
			Error:  codeTxFailed,
			Tier:   view.Tier,
			Reason: "待执行 argv 与事务两键对不上,拒绝执行",
			Detail: fmt.Sprintf("argv=%v", view.Argv),
		}
	}
	view.Name = intent.unit
	view.DesiredState = intent.desiredState
	args["name"] = intent.unit
	args["desired_state"] = intent.desiredState

	// 幂等先于档位分派:没有任何变更发生,也就没有需要授权的动作。
	if alreadyInDesiredState(view.DesiredState, obs) {
		recordAudit(toolApply, "noop", args, nil)
		return applyView{
			Tier:    view.Tier,
			Outcome: "noop",
			Scope:   view.Scope,
			Argv:    view.Argv,
			Reason:  "desired_state 已在位",
		}, nil
	}

	switch autonomy.Tier(view.Tier) {
	case autonomy.TierAuto:
		return runTransaction(view, args)
	case autonomy.TierConfirm:
		return runWithGrant(cfg, in, view, args)
	default:
		return runHuman(in, view, args)
	}
}

// runTransaction 真正执行变更:begin → propose → apply,三步任何一步失败都如实报错。
//
// propose 的两键(name + desired_state)从**被批准的 argv**反解而来,不是从请求
// 里抄:批准与执行必须是同一件事的两种写法,否则改了动词表就会批准另一个动作。
// 反解不出来就拒绝 —— 绝不猜,更不能退回请求里的期望状态。
func runTransaction(view previewView, args map[string]any) (applyView, *applyRejection) {
	intent, ok := serviceSetIntentFromArgv(view.Argv)
	if !ok {
		return deny(args, &applyRejection{
			Error:  codeTxFailed,
			Tier:   view.Tier,
			Reason: "待执行 argv 与事务两键对不上,拒绝执行",
			Detail: fmt.Sprintf("argv=%v", view.Argv),
		})
	}
	txID, err := runServiceSetTransaction(intent.unit, intent.desiredState)
	if err != nil {
		args["error"] = shortErrText(err)
		recordAudit(toolApply, "error", args, err)
		return applyView{}, &applyRejection{
			Error:  codeTxFailed,
			Tier:   view.Tier,
			Reason: "执行失败,事务未完成",
			Detail: shortErrText(err),
		}
	}
	args["tx_id"] = txID
	recordAudit(toolApply, "success", args, nil)
	return applyView{
		TxID:    txID,
		Tier:    view.Tier,
		Outcome: "applied",
		Scope:   view.Scope,
		Argv:    view.Argv,
	}, nil
}

// runWithGrant 走第二档:条子是必要条件,校验与记账在消费侧完成。
func runWithGrant(cfg *autonomy.Config, in applyIn, view previewView, args map[string]any) (applyView, *applyRejection) {
	if in.GrantID == "" {
		return deny(args, &applyRejection{
			Error:         codeGrantRequired,
			Tier:          view.Tier,
			RequiredScope: requiredScope(view),
			Reason:        "需要授权条子",
			Detail:        "请让有权签发的人执行 daedalus-tx grant add --scope <required_scope>,然后把条子 id 作为 grant_id 传入",
		})
	}
	// 审计只记条子 id:条子里的 note 与自报字段一律不进链。
	args["grant_id"] = in.GrantID

	scope, err := autonomy.ParseScope(view.Scope)
	if err != nil {
		return deny(args, &applyRejection{
			Error:  codeTxFailed,
			Tier:   view.Tier,
			Reason: "内部作用域不可解析",
			Detail: err.Error(),
		})
	}
	if rej := consumeGrant(cfg, in.GrantID, scope, time.Now()); rej != nil {
		rej.Tier = view.Tier
		return deny(args, rej)
	}

	// 条子通过 ⇒ 记账已完成,先记账再执行。执行结果直接决定 outcome。
	result, rej := runTransaction(view, args)
	if rej == nil {
		result.GrantID = in.GrantID
	}
	return result, rej
}

// runHuman 走第三档:条子不构成许可;只出待办,等人批准同一份 argv。
func runHuman(in applyIn, view previewView, args map[string]any) (applyView, *applyRejection) {
	pendingID := pendingIDFor(in.Kind, view.Name, view.DesiredState, view.Scope)
	args["pending_id"] = pendingID

	status, approval, err := loadApproval(pendingID, view.Argv, time.Now())
	switch status {
	case approvalUntrusted:
		// 目录/记录在审查之后被换掉的可能必须当拒绝处理,不能当"没有批准"。
		return deny(args, &applyRejection{
			Error:  codeApprovalUntrusted,
			Tier:   view.Tier,
			Reason: "批准记录不可信,拒绝执行",
			Detail: shortErrText(err),
		})
	case approvalMismatched:
		return deny(args, &applyRejection{
			Error:  codeApprovalMismatch,
			Tier:   view.Tier,
			Reason: "批准的不是这一条 argv(参数变了就是新动作)",
			Detail: "批准记录里的 argv_sha256 与本次将执行的 argv 不一致,请重新申请待办并重新批准",
		})
	case approvalStale:
		// 批准过期不是"没批准":重新出一份待办会把人已经批过的事实抹掉,
		// 而过期这件事必须让人看见 —— 所以单独一个码,要求重新申请、重新批。
		return deny(args, &applyRejection{
			Error:  codeApprovalStale,
			Tier:   view.Tier,
			Reason: "批准已过新鲜度窗口,拒绝执行",
			Detail: shortErrText(err),
		})
	case approvalTrusted:
		args["approved_by"] = approval.ApprovedBy
		result, rej := runTransaction(view, args)
		if rej == nil {
			result.PendingID = pendingID
			result.ApprovedBy = approval.ApprovedBy
		}
		return result, rej
	}

	// 没有批准记录 ⇒ 新出一份待办(同 id 覆盖,刷新有效期)。
	if err := writePending(pendingDoc{
		ID:           pendingID,
		Kind:         in.Kind,
		Name:         view.Name,
		DesiredState: view.DesiredState,
		Argv:         view.Argv,
		Scope:        view.Scope,
		Reason:       "tier=human (" + view.Reason + ")",
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:    time.Now().UTC().Add(pendingTTL).Format(time.RFC3339),
	}); err != nil {
		return deny(args, &applyRejection{
			Error:  codePendingWriteFailed,
			Tier:   view.Tier,
			Reason: "待办写入失败,无法申请批准",
			Detail: shortErrText(err),
		})
	}
	// 出待办不是拒绝:审计如实记 proposed(不出错、也没执行),证据链才说得通。
	recordAudit(toolApply, "proposed", args, nil)
	return applyView{}, &applyRejection{
		Error:      codeApprovalRequired,
		Tier:       view.Tier,
		PendingID:  pendingID,
		Argv:       view.Argv,
		ArgvSHA256: argvSHA256(view.Argv),
		Reason:     "需要人批准",
		Detail: fmt.Sprintf("待办 %s 已生成;人执行 daedalus-tx approve %s --expect-sha256 %s 后重新调用本工具",
			pendingID, pendingID, argvSHA256(view.Argv)),
	}
}

// deny 统一落 denied 审计并原样返回拒绝:审计与应答必须是同一份事实。
func deny(args map[string]any, rej *applyRejection) (applyView, *applyRejection) {
	args["error"] = rej.Error
	recordAudit(toolApply, "denied", args, nil)
	return applyView{}, rej
}

// alreadyInDesiredState 判定"没有变更可做"。只收三个不涉及中间态的组合:
// started 且已在跑、enabled 且已启用、disabled 且已停用。
// stopped 不算幂等 —— 对 failed 单元执行 stop 会清掉失败状态,那不是 noop;
// restarted 永远有中断副作用,不能省。
func alreadyInDesiredState(desiredState string, obs observation) bool {
	if !obs.known {
		return false
	}
	switch desiredState {
	case "started":
		return obs.running
	case "enabled":
		return obs.enabled
	case "disabled":
		return !obs.enabled
	default:
		return false
	}
}

// requiredScope 保证拒绝里恒有非空的作用域清单:空数组会被客户端读成"不需要"。
func requiredScope(view previewView) []string {
	if len(view.RequiredScope) != 0 {
		return view.RequiredScope
	}
	return []string{view.Scope}
}

// baseAuditArgs 是审计 args 的稳定骨架:键齐(值可为空),拒绝与成功同形,
// 下游按固定字段消费,不必猜哪次调用少了哪个键。
func baseAuditArgs(in applyIn) map[string]any {
	return map[string]any{
		"kind":          in.Kind,
		"name":          in.Name,
		"desired_state": in.DesiredState,
		"tier":          "",
		"grant_id":      "",
		"tx_id":         "",
		"decision_path": []string{},
		"actor":         in.Actor,
	}
}
