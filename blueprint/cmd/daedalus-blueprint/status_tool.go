package main

// status_tool.go —— blueprint_status / blueprint_remove 工具(todo 20)。
//
// blueprint_status:只读查询蓝图当前部署状态——目标路径存在与否、内容 sha256
// 前 12 位、plan store 中该蓝图的活动计划数。无副作用、无子进程调用。
//
// blueprint_remove:经确认令牌删除已应用的蓝图配置。v1 简化:remove 不走
// plan store,直接对 "remove:"+name 生成单次 token;删文件(存在才删)→
// reload(经 a.execCmd 注入缝)→ audit → 返回 {removed, config_path}。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/blueprint"
)

// statusIn 是 blueprint_status 的输入。
type statusIn struct {
	Name string `json:"name" jsonschema:"蓝图 id,如 nginx-vhost。"`
}

// statusOut 是 blueprint_status 的输出。
type statusOut struct {
	Name        string `json:"name"`
	TargetPath  string `json:"target_path"`
	Installed   bool   `json:"installed"`
	ContentHash string `json:"content_hash"` // sha256 前 12 位;未安装则空串
	ActivePlans int    `json:"active_plans"` // plan store 中该蓝图的活动计划数
}

// removeIn 是 blueprint_remove 的输入。
type removeIn struct {
	Name         string `json:"name" jsonschema:"蓝图 id,如 nginx-vhost。"`
	PlanID       string `json:"plan_id" jsonschema:"先前 blueprint_apply 的 plan_id(该 plan 必须已应用)。"`
	ConfirmToken string `json:"confirm_token" jsonschema:"针对 remove:<name> 的单次有效确认令牌。"`
}

// removeOut 是 blueprint_remove 的输出。
type removeOut struct {
	Removed    bool   `json:"removed"`
	ConfigPath string `json:"config_path"`
}

// registerStatusTool 注册 blueprint_status(只读)。
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

// handleStatus 返回 statusIn handler 闭包(只读,无副作用)。
func handleStatus(a *app) func(context.Context, *mcp.CallToolRequest, statusIn) (*mcp.CallToolResult, any, error) {
	return func(_ context.Context, _ *mcp.CallToolRequest, in statusIn) (*mcp.CallToolResult, any, error) {
		cb, ok := a.reg.get(in.Name)
		if !ok {
			return toolErrorf("blueprint %q 不存在", in.Name), nil, nil
		}

		// 由 OutputPathTmpl 推导目标路径(无参数时无法替换 {param},v1 用 "*" 占位
		// 说明"存在性按 output_dirs 下的实际文件判定";更精确的做法是遍历 outputDirs
		// 找匹配前缀的文件——v1 简化:报告蓝图已知信息 + 计划数)。
		targetPath := cb.Blueprint.OutputPathTmpl

		// 内容哈希:查 outputDirs 下是否存在该蓝图渲染出的文件(v1 用目录扫描近似,
		// 精确到"output_dirs 任一目录下非空文件存在"即视为已安装)。
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

		// 活动计划数:plan store 中 Name 匹配的计划数。
		activePlans := a.plans.countByName(in.Name)
		out := statusOut{
			Name:        in.Name,
			TargetPath:  targetPath,
			Installed:   installed,
			ContentHash: contentHash,
			ActivePlans: activePlans,
		}
		return jsonResult(out), nil, nil
	}
}

// registerRemoveTool 注册 blueprint_remove(写型:经确认令牌删除配置)。
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

// handleRemove 返回 removeIn handler 闭包。
func handleRemove(a *app) func(context.Context, *mcp.CallToolRequest, removeIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in removeIn) (*mcp.CallToolResult, any, error) {
		cb, ok := a.reg.get(in.Name)
		if !ok {
			return toolErrorf("blueprint %q 不存在", in.Name), nil, nil
		}

		// F1/F2 复审修复:remove 必须关联一个**已成功 apply** 的 plan,且
		// confirm_token 必须与 apply 时生成并存入 plan store 的 RemoveToken
		// **逐字比对**(任意非空串不再通过)。要求:
		//   a) 用户提供 plan_id,plan 存在且 Name 匹配;
		//   b) plan.RemoveToken 非空(证明 apply 成功且已生成 remove 令牌);
		//   c) 用户 confirm_token == plan.RemoveToken.Token(真实配对);
		//   d) VerifyConfirmToken 消费该 remove 令牌(单次有效,防重放)。
		if in.PlanID == "" {
			return toolErrorf("remove 必须提供 plan_id(先前 blueprint_apply 的 plan)"), nil, nil
		}
		plan, ok := a.plans.get(in.PlanID)
		if !ok {
			return toolErrorf("plan %q 不存在(先 blueprint_render + apply)", in.PlanID), nil, nil
		}
		if plan.Name != in.Name {
			return toolErrorf("plan %q 属于蓝图 %q,与入参 %q 不匹配", in.PlanID, plan.Name, in.Name), nil, nil
		}
		// 校验该 plan 已成功 apply(Applied 标志,由 apply 成功时置位);不再用
		// VerifyConfirmToken 做探测——那会误消费尚未使用的 apply 令牌(F2 R1 修复)。
		if !plan.Applied {
			return toolErrorf("plan %q 尚未应用(需先 blueprint_apply)", in.PlanID), nil, nil
		}
		// RemoveToken 必须存在(apply 成功时生成),且与用户提供的逐字一致。
		if plan.RemoveToken.Token == "" {
			return toolErrorf("plan %q 无 remove 令牌(apply 未完成或 plan 过期)", in.PlanID), nil, nil
		}
		if in.ConfirmToken != plan.RemoveToken.Token {
			return toolErrorf("confirm_token 与 plan %q 的 remove 令牌不匹配", in.PlanID), nil, nil
		}
		// 消费 remove 令牌(单次有效,防重放)。
		if err := blueprint.VerifyConfirmToken("remove:"+in.Name, blueprint.ConfirmToken{
			Token:   in.ConfirmToken,
			PlanID:  "remove:" + in.Name,
			Expires: plan.RemoveToken.Expires,
		}); err != nil {
			return toolError(err), nil, nil
		}

		// 定位并删除目标文件:仅删除 plan.Target(outputDirs 内,纵深防御已由
		// render/apply 校验;此处直接以 plan.Target 为准,不再扫目录防误删)。
		removed := false
		configPath := plan.Target
		if validateOutputPath(a.outputDirs, plan.Target) {
			if err := os.Remove(plan.Target); err == nil {
				removed = true
			}
		}
		if !removed {
			return toolErrorf("蓝图 %q 目标文件不存在或不可删除", in.Name), nil, nil
		}

		// reload。
		if err := runReload(ctx, a, cb.Blueprint.ReloadService); err != nil {
			return toolErrorf("remove 后 reload 失败: %v", err), nil, nil
		}

		// audit。
		writeBlueprintAudit("blueprint_remove", map[string]any{
			"name": in.Name, "plan_id": in.PlanID, "config_path": configPath,
		}, "ok")

		out := removeOut{Removed: true, ConfigPath: configPath}
		return jsonResult(out), nil, nil
	}
}
