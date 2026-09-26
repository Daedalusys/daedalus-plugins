package main

// status_tool.go —— blueprint_status / blueprint_remove 工具。
//
// blueprint_status:只读查询部署状态(目标路径存在与否、内容 sha256 前 12 位、
// 活动计划数),无副作用、无子进程调用。blueprint_remove:经确认令牌删配置 →
// reload(经 a.execCmd 注入缝)→ 每次调用落恰一条审计(完成走 legacy ok 条目,
// 被拒 / 失败走 recordAudit)→ 返回 {removed, config_path}。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/blueprint"
)

type statusIn struct {
	Name string `json:"name" jsonschema:"蓝图 id,如 nginx-vhost。"`
}

type statusOut struct {
	Name        string `json:"name"`
	TargetPath  string `json:"target_path"`
	Installed   bool   `json:"installed"`
	ContentHash string `json:"content_hash"` // sha256 前 12 位;未安装则空串
	ActivePlans int    `json:"active_plans"` // plan store 中该蓝图的活动计划数
}

type removeIn struct {
	Name         string `json:"name" jsonschema:"蓝图 id,如 nginx-vhost。"`
	PlanID       string `json:"plan_id" jsonschema:"先前 blueprint_apply 的 plan_id(该 plan 必须已应用)。"`
	ConfirmToken string `json:"confirm_token" jsonschema:"针对 remove:<name> 的单次有效确认令牌。"`
}

type removeOut struct {
	Removed    bool   `json:"removed"`
	ConfigPath string `json:"config_path"`
}

func registerStatusTool(server *mcp.Server, a *app) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blueprint_status",
		Description: "查询蓝图当前部署状态:目标路径存在性、内容哈希、活动计划数。只读。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"name": {Type: "string", Description: "蓝图 id,如 nginx-vhost。"},
			},
			Required: []string{"name"},
		},
		Annotations: readOnlyAnnotations(),
	}, handleStatus(a))
}

// handleStatus 是 blueprint_status 的审计入口:不存在的蓝图名属入参校验
// 拒绝 denied,序列化故障 error,其余 success。args 只记录入参 name;
// 目录扫描的读失败本就被静默容忍,不进链。
func handleStatus(a *app) func(context.Context, *mcp.CallToolRequest, statusIn) (*mcp.CallToolResult, any, error) {
	return func(_ context.Context, _ *mcp.CallToolRequest, in statusIn) (*mcp.CallToolResult, any, error) {
		res, outcome, cause := statusResult(a, in)
		recordAudit("blueprint_status", outcome, map[string]any{"name": in.Name}, cause)
		return res, nil, nil
	}
}

func statusResult(a *app, in statusIn) (*mcp.CallToolResult, string, error) {
	cb, ok := a.reg.get(in.Name)
	if !ok {
		err := fmt.Errorf("blueprint %q 不存在", in.Name)
		return toolError(err), "denied", err
	}

	// v1 简化:无参数时无法替换 {param},故扫描 outputDirs 近似判定已安装,
	// 命中即把 targetPath 修正为实际文件。
	targetPath := cb.Blueprint.OutputPathTmpl
	installed := false
	contentHash := ""
	for _, dir := range a.outputDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			full := dir + "/" + e.Name()
			data, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			installed = true
			sum := sha256.Sum256(data)
			contentHash = hex.EncodeToString(sum[:])[:12]
			targetPath = full
			break
		}
		if installed {
			break
		}
	}

	activePlans := a.plans.countByName(in.Name)
	out := statusOut{
		Name:        in.Name,
		TargetPath:  targetPath,
		Installed:   installed,
		ContentHash: contentHash,
		ActivePlans: activePlans,
	}
	res := jsonResult(out)
	if res.IsError {
		return res, "error", nil
	}
	return res, "success", nil
}

func registerRemoveTool(server *mcp.Server, a *app) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blueprint_remove",
		Description: "经确认令牌删除已应用的蓝图配置并 reload 服务。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"name":          {Type: "string", Description: "蓝图 id,如 nginx-vhost。"},
				"plan_id":       {Type: "string", Description: "可选 plan_id。"},
				"confirm_token": {Type: "string", Description: "针对 remove:<name> 的单次有效确认令牌。"},
			},
			Required: []string{"name", "plan_id", "confirm_token"},
		},
		Annotations: destructiveAnnotations(),
	}, handleRemove(a))
}

// handleRemove 是移除工具入口的审计 choke point:每次调用恰记一条——完成
// 移除已由流程内 legacy writeBlueprintAudit("ok") 落链,此处只补被拒 / 失败
// 结局,避免双计。args 只记录 name / plan_id,confirm_token 值严禁进链。
func handleRemove(a *app) func(context.Context, *mcp.CallToolRequest, removeIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in removeIn) (*mcp.CallToolResult, any, error) {
		res, outcome, cause := removeResult(ctx, a, in)
		if outcome != "success" {
			recordAudit("blueprint_remove", outcome, map[string]any{
				"name": in.Name, "plan_id": in.PlanID,
			}, cause)
		}
		return res, nil, nil
	}
}

// removeResult 判定移除调用的结局:plan / 令牌各校验门拒绝 denied,
// 删文件或 reload 执行失败 error,完成路径保留 legacy ok 条目并返回 success。
func removeResult(ctx context.Context, a *app, in removeIn) (*mcp.CallToolResult, string, error) {
	cb, ok := a.reg.get(in.Name)
	if !ok {
		err := fmt.Errorf("blueprint %q 不存在", in.Name)
		return toolError(err), "denied", err
	}

	// remove 必须关联一个**已成功 apply** 的 plan,且 confirm_token 必须与
	// apply 时生成并存入 plan store 的 RemoveToken **逐字比对**(任意非空串不再
	// 通过);令牌经 VerifyConfirmToken 消费(单次有效,防重放)。
	if in.PlanID == "" {
		err := fmt.Errorf("remove 必须提供 plan_id(先前 blueprint_apply 的 plan)")
		return toolError(err), "denied", err
	}
	plan, ok := a.plans.get(in.PlanID)
	if !ok {
		err := fmt.Errorf("plan %q 不存在(先 blueprint_render + apply)", in.PlanID)
		return toolError(err), "denied", err
	}
	if plan.Name != in.Name {
		err := fmt.Errorf("plan %q 属于蓝图 %q,与入参 %q 不匹配", in.PlanID, plan.Name, in.Name)
		return toolError(err), "denied", err
	}
	// 校验该 plan 已成功 apply(Applied 标志,由 apply 成功时置位);不用
	// VerifyConfirmToken 做探测——那会误消费尚未使用的 apply 令牌。
	if !plan.Applied {
		err := fmt.Errorf("plan %q 尚未应用(需先 blueprint_apply)", in.PlanID)
		return toolError(err), "denied", err
	}
	// RemoveToken 必须存在(apply 成功时生成)。
	if plan.RemoveToken.Token == "" {
		err := fmt.Errorf("plan %q 无 remove 令牌(apply 未完成或 plan 过期)", in.PlanID)
		return toolError(err), "denied", err
	}
	if in.ConfirmToken != plan.RemoveToken.Token {
		err := fmt.Errorf("confirm_token 与 plan %q 的 remove 令牌不匹配", in.PlanID)
		return toolError(err), "denied", err
	}
	if err := blueprint.VerifyConfirmToken("remove:"+in.Name, blueprint.ConfirmToken{
		Token:   in.ConfirmToken,
		PlanID:  "remove:" + in.Name,
		Expires: plan.RemoveToken.Expires,
	}); err != nil {
		return toolError(err), "denied", err
	}

	// 仅删除 plan.Target(纵深防御已由 render/apply 校验;不再扫目录防误删)。
	removed := false
	configPath := plan.Target
	if validateOutputPath(a.outputDirs, plan.Target) {
		if err := os.Remove(plan.Target); err == nil {
			removed = true
		}
	}
	if !removed {
		err := fmt.Errorf("蓝图 %q 目标文件不存在或不可删除", in.Name)
		return toolError(err), "error", err
	}

	if err := runReload(ctx, a, cb.Blueprint.ReloadService); err != nil {
		reloadErr := fmt.Errorf("remove 后 reload 失败: %v", err)
		return toolError(reloadErr), "error", reloadErr
	}

	writeBlueprintAudit("blueprint_remove", map[string]any{
		"name": in.Name, "plan_id": in.PlanID, "config_path": configPath,
	}, "ok")

	out := removeOut{Removed: true, ConfigPath: configPath}
	res := jsonResult(out)
	if res.IsError {
		return res, "error", nil
	}
	return res, "success", nil
}
