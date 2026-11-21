// rollback.go —— tx_rollback:按 journal 里的目标作用域重新过档位,再决定是否回滚。
//
// 回滚不是免票通道:一个当初被拒绝的变更,其回滚同样可能碰到危险对象或不可观测的
// 属性。这里从 journal 的每一步重建作用域与属性快照,重跑 Classify;任一步落在
// 第三档就整笔拒绝,且 rollback 子命令一次都不调用 —— 失败发生在副作用之前。
//
// 与 tx_apply 的差异:apply 只需要一个目标;回滚的目标集合来自既有 steps,所以
// 判定取"最严的那一步"。未知适配器 / 缺参数 / 名称非法一律 fail-closed,
// 不猜目标,也不把"无法判定"当成"自动通过"。
package main

import (
	"encoding/json"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
)

const (
	// toolRollback 是本工具在审计链里的名字(与 manifest.tools 逐字一致)。
	toolRollback = "tx_rollback"
	// codeRollbackDenied:目标重新判定为第三档。
	codeRollbackDenied = "rollback_denied"
	// codeNothingToRollback:事务里没有可重建作用域的步骤。
	codeNothingToRollback = "nothing_to_rollback"
	// codeUnsupportedRollbackTarget:步骤适配器/参数无法映射成受控作用域。
	codeUnsupportedRollbackTarget = "unsupported_rollback_target"
)

type rollbackIn struct {
	TxID string `json:"tx_id"`
}

// rollbackView 是执行成功时的应答。
type rollbackView struct {
	TxID    string `json:"tx_id"`
	Outcome string `json:"outcome"`
	Tier    string `json:"tier"`
}

// rollbackRejection 是拒绝面:outcome 恒为 denied(契约里只有 rolled_back|denied),
// error 是机器可读码,tier 是重新判定得到的档位。
type rollbackRejection struct {
	Error   string `json:"error"`
	TxID    string `json:"tx_id"`
	Outcome string `json:"outcome"`
	Tier    string `json:"tier,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// txRollback 是"重新判定 → 可能执行"的完整流程。审计在这里统一写:拒绝与成功
// 都必须留下同形的证据(tx_id / tier / 判定来源)。
func txRollback(cfg *autonomy.Config, in rollbackIn) (rollbackView, *rollbackRejection) {
	args := map[string]any{
		"tx_id":         in.TxID,
		"tier":          "",
		"scope":         []string{},
		"decision_path": []string{},
	}
	if !txIDPattern.MatchString(in.TxID) {
		return denyRollback(args, &rollbackRejection{
			Error:   codeInvalidTxID,
			TxID:    in.TxID,
			Outcome: "denied",
			Reason:  "事务 ID 形状非法",
			Detail:  "tx_id 必须是 16 位小写十六进制",
		})
	}

	doc, serr := readJournal(in.TxID)
	if serr != nil {
		args["error"] = serr.Error
		recordAudit(toolRollback, "error", args, nil)
		return rollbackView{}, &rollbackRejection{
			Error:   serr.Error,
			TxID:    in.TxID,
			Outcome: "denied",
			Reason:  "读取事务日志失败",
			Detail:  serr.Detail,
		}
	}
	// 没有步骤就没有可判定的目标:拒绝而不是把"无目标"当作"自动通过"。
	if len(doc.Steps) == 0 {
		return denyRollback(args, &rollbackRejection{
			Error:   codeNothingToRollback,
			TxID:    in.TxID,
			Outcome: "denied",
			Reason:  "事务没有可回滚的步骤",
		})
	}

	tier := autonomy.TierAuto
	scopes := make([]string, 0, len(doc.Steps))
	reasons := make([]string, 0, len(doc.Steps))
	for _, raw := range doc.Steps {
		var step struct {
			Adapter string          `json:"adapter"`
			Args    json.RawMessage `json:"args"`
		}
		if err := json.Unmarshal(raw, &step); err != nil {
			return denyRollback(args, &rollbackRejection{
				Error:   codeUnsupportedRollbackTarget,
				TxID:    in.TxID,
				Outcome: "denied",
				Reason:  "步骤无法解析,无法重建回滚目标",
				Detail:  shortErrText(err),
			})
		}
		if step.Adapter != adapterServiceSet {
			return denyRollback(args, &rollbackRejection{
				Error:   codeUnsupportedRollbackTarget,
				TxID:    in.TxID,
				Outcome: "denied",
				Reason:  "步骤适配器不在本工具可判定的范围内",
				Detail:  "只支持 " + adapterServiceSet + ",收到 " + step.Adapter,
			})
		}
		var stepArgs serviceSetStep
		if err := json.Unmarshal(step.Args, &stepArgs); err != nil {
			return denyRollback(args, &rollbackRejection{
				Error:   codeUnsupportedRollbackTarget,
				TxID:    in.TxID,
				Outcome: "denied",
				Reason:  "步骤参数无法解析,无法重建回滚目标",
				Detail:  shortErrText(err),
			})
		}
		unit, err := normalizeUnitName(stepArgs.Name)
		if err != nil {
			return denyRollback(args, &rollbackRejection{
				Error:   codeUnsupportedRollbackTarget,
				TxID:    in.TxID,
				Outcome: "denied",
				Reason:  "步骤目标不是可判定的 service 单元",
				Detail:  shortErrText(err),
			})
		}
		// 属性在回滚前重新观测:签发/首次执行时的档位不算数。
		view, serr := buildPreview(stepArgs.DesiredState, unit, domainUser, cfg, observeUnit(unit))
		if serr != nil {
			return denyRollback(args, &rollbackRejection{
				Error:   codeUnsupportedRollbackTarget,
				TxID:    in.TxID,
				Outcome: "denied",
				Reason:  "步骤目标无法映射成受控作用域",
				Detail:  serr.Detail,
			})
		}
		scopes = append(scopes, view.Scope)
		reasons = append(reasons, view.Reason)
		tier = strictestTier(tier, autonomy.Tier(view.Tier))
	}
	args["tier"] = string(tier)
	args["scope"] = scopes
	args["decision_path"] = reasons

	// 只要有一环落在第三档,整笔回滚就拒绝:回滚会作用到全部步骤,不能挑着做。
	if tier == autonomy.TierHuman {
		return denyRollback(args, &rollbackRejection{
			Error:   codeRollbackDenied,
			TxID:    in.TxID,
			Outcome: "denied",
			Tier:    string(tier),
			Reason:  "回滚目标属第三档,回滚不是免票通道",
			Detail:  "该事务至少有一个目标当前判定为人亲手;请由人执行 daedalus-tx rollback " + in.TxID,
		})
	}

	stdout, stderrText, rc, err := runTx("rollback", in.TxID)
	if err != nil {
		args["error"] = codeTxFailed
		recordAudit(toolRollback, "error", args, err)
		return rollbackView{}, &rollbackRejection{
			Error:   codeTxFailed,
			TxID:    in.TxID,
			Outcome: "denied",
			Tier:    string(tier),
			Reason:  "回滚失败,事务可能只回滚了一部分",
			Detail:  shortErrText(err),
		}
	}
	if rc != 0 {
		cause := cliFailure("rollback", rc, stdout, stderrText)
		args["error"] = codeTxFailed
		recordAudit(toolRollback, "error", args, cause)
		return rollbackView{}, &rollbackRejection{
			Error:   codeTxFailed,
			TxID:    in.TxID,
			Outcome: "denied",
			Tier:    string(tier),
			Reason:  "回滚失败,事务可能只回滚了一部分",
			Detail:  shortErrText(cause),
		}
	}
	recordAudit(toolRollback, "success", args, nil)
	return rollbackView{TxID: in.TxID, Outcome: "rolled_back", Tier: string(tier)}, nil
}

// denyRollback 统一落 denied 审计并原样返回拒绝:审计与应答是同一份事实。
func denyRollback(args map[string]any, rej *rollbackRejection) (rollbackView, *rollbackRejection) {
	args["error"] = rej.Error
	recordAudit(toolRollback, "denied", args, nil)
	return rollbackView{}, rej
}

// strictestTier 取两个档位里更严的一个。第三档高于第二档高于第一档;
// 表外取值按最严处理,避免将来新增档位时静默放行。
func strictestTier(a, b autonomy.Tier) autonomy.Tier {
	if tierRank(b) > tierRank(a) {
		return b
	}
	return a
}

func tierRank(t autonomy.Tier) int {
	switch t {
	case autonomy.TierAuto:
		return 1
	case autonomy.TierConfirm:
		return 2
	default:
		return 3
	}
}
