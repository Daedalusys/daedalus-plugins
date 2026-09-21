package main

// apply_tool.go —— blueprint_apply 工具(todo 19)。
//
// 流程(与 plan 规格逐条对应):
//  1. plan store 按 plan_id 取 plan;不存在即拒;
//  2. plan.Name 与入参 name 一致性校验(防串用);
//  3. confirm_token 校验(VerifyConfirmToken,成功即消费,单次有效);
//  4. 目标路径再次校验 ∈ outputDirs(纵深防御,防 plan store 被篡改);
//  5. 读旧文件快照 → 写入渲染结果(0o644);
//  6. post_check:把 cb.postCheckCmd 脚本写临时文件 → sh <tmp> argv 直发,
//     30s 超时;stdout/stderr 不进 audit(防 secret 泄漏);
//  7. reload:systemctl restart <ReloadService>,30s 超时;
//  8. 失败逆序回滚:post_check 或 reload 失败 → 有旧文件恢复旧内容,否则删新文件;
//  9. audit 写条目(tool="blueprint_apply", args 不含渲染内容, outcome=ok/error,
//     写失败静默容忍,与 daedalus-tx 同纪律);
// 10. 返回 ApplyResult(tx_id="(v1-direct)",applied_at,config_path,post_check_ok,reload_ok)。
//
// 执行模型 v1-direct:不经 daedalus-tx 子命令链(tx 的 blueprint.write 适配器
// 归后续 plan);post_check / reload 两个子进程调用统一经 a.execCmd 注入缝,
// 测试替换为假实现避免真实系统调用。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/audit"
	"github.com/Daedalusys/daedalus-sdk/blueprint"
	"github.com/Daedalusys/daedalus-sdk/shellpolicy"
)

// applyIn 是 blueprint_apply 的输入。
type applyIn struct {
	Name         string `json:"name" jsonschema:"蓝图 id,如 nginx-vhost。"`
	PlanID       string `json:"plan_id" jsonschema:"blueprint_render 返回的 plan_id。"`
	ConfirmToken string `json:"confirm_token" jsonschema:"blueprint_render 返回的单次有效确认令牌。"`
}

// applyOut 是 blueprint_apply 的输出。
type applyOut struct {
	TxID        string `json:"tx_id"`
	AppliedAt   string `json:"applied_at"`
	ConfigPath  string `json:"config_path"`
	PostCheckOK bool   `json:"post_check_ok"`
	ReloadOK    bool   `json:"reload_ok"`
	// RemoveToken 是后续 blueprint_remove 需出示的单次令牌(F2 R2 修复:必须回传客户端,否则 remove 永不可达)。
	RemoveToken string `json:"remove_token"`
}

// registerApplyTool 注册 blueprint_apply(写型:经确认令牌落盘 + reload)。
func registerApplyTool(server *mcp.Server, a *app) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blueprint_apply",
		Description: "经确认令牌应用蓝图:写入渲染配置、执行 post_check 校验、reload 服务。失败自动逆序回滚。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"name":          {Type: "string", Description: "蓝图 id,如 nginx-vhost。"},
				"plan_id":       {Type: "string", Description: "blueprint_render 返回的 plan_id。"},
				"confirm_token": {Type: "string", Description: "blueprint_render 返回的单次有效确认令牌。"},
			},
			Required: []string{"name", "plan_id", "confirm_token"},
		},
		Annotations: destructiveAnnotations(),
	}, handleApply(a))
}

// handleApply 返回 applyIn handler 闭包。
func handleApply(a *app) func(context.Context, *mcp.CallToolRequest, applyIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in applyIn) (*mcp.CallToolResult, any, error) {
		// ① plan store 取 plan。
		plan, ok := a.plans.get(in.PlanID)
		if !ok {
			return toolErrorf("plan %q 不存在(先 blueprint_render)", in.PlanID), nil, nil
		}

		// ② name 与 plan 一致性校验(防串用)。
		if plan.Name != in.Name {
			return toolErrorf("plan %q 属于蓝图 %q,与入参 %q 不匹配", in.PlanID, plan.Name, in.Name), nil, nil
		}

		// ③ confirm_token 校验(成功即消费,单次有效)。
		// 先比对用户提供的 token 与 plan store 中 render 生成的真实 token
		// (VerifyConfirmToken 只校验"非空/plan_id 匹配/未消费/未过期",
		// 不持有真实 token——配对语义必须由调用方先比对 token 串)。
		if plan.Token.Token == "" {
			return toolErrorf("plan %q 无关联确认令牌(render 异常)", in.PlanID), nil, nil
		}
		if in.ConfirmToken != plan.Token.Token {
			return toolErrorf("confirm_token 与 plan %q 不匹配", in.PlanID), nil, nil
		}
		if err := blueprint.VerifyConfirmToken(in.PlanID, blueprint.ConfirmToken{
			Token:   in.ConfirmToken,
			PlanID:  in.PlanID,
			Expires: plan.Token.Expires,
		}); err != nil {
			return toolError(err), nil, nil
		}

		// ④ 目标路径白名单(纵深防御,防 plan store 被篡改)。
		// F1/F2 复审修复:除词法前缀外,必须解析符号链接确认真实路径仍在
		// 白名单内——否则 outputDirs 下若有指向 /etc/shadow 等敏感文件的
		// symlink,词法校验通过但写入实际落到白名单外。
		if !validateOutputPath(a.outputDirs, plan.Target) {
			return toolErrorf("目标路径 %q 越出允许目录白名单", plan.Target), nil, nil
		}
		if err := validateOutputPathResolved(a.outputDirs, plan.Target); err != nil {
			return toolError(err), nil, nil
		}

		// 取编译蓝图(需 post_check 脚本与 reload 服务名)。
		cb, ok := a.reg.get(in.Name)
		if !ok {
			return toolErrorf("blueprint %q 不存在", in.Name), nil, nil
		}

		// ⑤ 旧文件快照 + 写入渲染结果。
		hadOld := false
		var oldContent []byte
		if data, err := os.ReadFile(plan.Target); err == nil {
			hadOld = true
			oldContent = data
		}
		if err := os.MkdirAll(filepath.Dir(plan.Target), 0o755); err != nil {
			return toolErrorf("创建目标目录失败: %v", err), nil, nil
		}
		if err := os.WriteFile(plan.Target, []byte(plan.Rendered), 0o644); err != nil {
			return toolErrorf("写入配置失败: %v", err), nil, nil
		}

		// rollback 闭包:失败时恢复旧快照或删除新文件。回滚本身的错误
		// (F2 审查修复)不能被 `_ =` 吞掉——回滚失败必须回传给调用方,
		// 否则"配置已破坏但回滚也失败"的灾难状态会静默通过。
		var rollbackErr error
		rollback := func() {
			if hadOld {
				if err := os.WriteFile(plan.Target, oldContent, 0o644); err != nil {
					rollbackErr = fmt.Errorf("回滚恢复旧文件失败: %w", err)
				}
			} else {
				if err := os.Remove(plan.Target); err != nil && !os.IsNotExist(err) {
					rollbackErr = fmt.Errorf("回滚删除新文件失败: %w", err)
				}
			}
		}

		// ⑥ post_check(脚本非空才执行)。params 经 plan.Params 传入,行内
		// {param} 占位符渲染;argv 直发(无 shell 求值,F1/F2 复审 3b 修复)。
		postCheckOK := true
		if cb.postCheckCmd != "" {
			if err := runPostCheck(ctx, a, cb.postCheckCmd, plan.Params); err != nil {
				rollback()
				writeBlueprintAudit("blueprint_apply", map[string]any{
					"plan_id": in.PlanID, "name": in.Name, "target": plan.Target,
				}, "error")
				if rollbackErr != nil {
					return toolErrorf("post_check 失败(已回滚): %v; 回滚错误: %v", err, rollbackErr), nil, nil
				}
				return toolErrorf("post_check 失败(已回滚): %v", err), nil, nil
			}
		}

		// ⑦ reload。
		if err := runReload(ctx, a, cb.Blueprint.ReloadService); err != nil {
			rollback()
			writeBlueprintAudit("blueprint_apply", map[string]any{
				"plan_id": in.PlanID, "name": in.Name, "target": plan.Target,
			}, "error")
			if rollbackErr != nil {
				return toolErrorf("reload 失败(已回滚): %v; 回滚错误: %v", err, rollbackErr), nil, nil
			}
			return toolErrorf("reload 失败(已回滚): %v", err), nil, nil
		}

		// ⑧ 成功:为该 plan 生成 remove 确认令牌并回写 plan store
		// (F1/F2 复审 2a 修复:remove 必须有真实的 token 生产路径,apply 是
		// 唯一生产点;remove 校验时比对 store 中的 RemoveToken)。
		// F2 R1 修复:同步置位 Applied 标志,handleRemove 改用它判断"已应用"。
		plan.RemoveToken = blueprint.GenerateConfirmToken("remove:" + in.Name)
		plan.Applied = true
		a.plans.put(in.PlanID, plan)

		// ⑨ audit(成功)。
		writeBlueprintAudit("blueprint_apply", map[string]any{
			"plan_id": in.PlanID, "name": in.Name, "target": plan.Target,
		}, "ok")

		// ⑩ 返回结果。
		out := applyOut{
			TxID:        "(v1-direct)",
			AppliedAt:   time.Now().UTC().Format(time.RFC3339),
			ConfigPath:  plan.Target,
			PostCheckOK: postCheckOK,
			ReloadOK:    true,
			RemoveToken: plan.RemoveToken.Token,
		}
		return jsonResult(out), nil, nil
	}
}

// runPostCheck 执行蓝图 post_check 命令序列(F1/F2 复审 3b 修复)。
//
// 原实现把 post_check 当 shell 脚本经 `sh <tmp>` 执行——即便做了静态扫描,
// `evil=$(whoami); $evil` 与 `sudo whoami` 等变量间接/提权路径仍可绕过,
// 且静态扫描本质无法穷尽 shell 语义。**根治:post_check 不再经过任何 shell
// 解释器**,改为引号感知的**逐行 argv 直发**:
//
//   - 脚本每行 = 一条命令:首个 token 为命令名(必须 ∈ PostCheckAllowCommands,
//     白名单外即整体拒绝,不执行);
//   - 每行经 quoteSplit 做引号感知分词 → (name, argv),整行作为 argv 直发
//     (execCmd),无 shell 求值:变量展开/命令替换/管道/重定向/sudo 提权
//     全部不可能发生;
//   - 行内 `{param}` 占位符先经 params 渲染(与 output_path_template 同约定);
//   - `#` 注释行与空行跳过;任一命令失败(非零退出)即整体失败。
//
// 副作用:post_check 的能力从"任意 shell"收敛为"白名单命令序列"——这是
// 安全边界要求的取舍;6 个官方蓝图脚本已同步改造为纯命令行格式。
func runPostCheck(ctx context.Context, a *app, script string, params map[string]any) error {
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = renderPostCheckLine(line, params)
		argv, err := quoteSplit(line)
		if err != nil {
			return fmt.Errorf("post_check 行解析失败 %q: %w", line, err)
		}
		if len(argv) == 0 {
			continue
		}
		base := filepath.Base(argv[0])
		if !shellpolicy.IsPostCheckAllowed(base) {
			return fmt.Errorf("post_check 命令 %q 不在白名单", base)
		}
		runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if _, err := a.execCmd(runCtx, argv[0], argv[1:]...); err != nil {
			cancel()
			return fmt.Errorf("post_check 命令 %q 失败: %w", base, err)
		}
		cancel()
	}
	return nil
}

// renderPostCheckLine 把行内 `{param}` 占位符替换为 params 值。
//
// 与 output_path_template 的 {param} 渲染同约定;缺失参数按空串处理
// (占位符保留原样会导致命令语义错误,故替换为空串并容忍)。
func renderPostCheckLine(line string, params map[string]any) string {
	for k, v := range params {
		s, ok := v.(string)
		if !ok {
			continue
		}
		line = strings.ReplaceAll(line, "{"+k+"}", s)
	}
	return line
}

// quoteSplit 做引号感知的 argv 分词(不经 shell)。
//
// 把一行按空白切分为 argv 元素,双引号 `"..."` 内整体作为一个元素
// (内容保留原样,不做任何转义/展开)。单引号同样处理。用于 post_check
// 行 → argv 直发,替代 shell 解释(无变量/管道/重定向求值)。
func quoteSplit(line string) ([]string, error) {
	var argv []string
	var cur []rune
	inQuote := rune(0) // 0=无引号;'"'=双引号;'\''=单引号
	flush := func() {
		if len(cur) > 0 {
			argv = append(argv, string(cur))
			cur = cur[:0]
		}
	}
	for _, r := range line {
		switch {
		case inQuote != 0:
			if r == inQuote {
				inQuote = 0
			} else {
				cur = append(cur, r)
			}
		case r == '"' || r == '\'':
			inQuote = r
		case r == ' ' || r == '\t':
			flush()
		default:
			cur = append(cur, r)
		}
	}
	if inQuote != 0 {
		return nil, fmt.Errorf("未闭合引号 %q", string(inQuote))
	}
	flush()
	return argv, nil
}

// runReload 经 systemctl restart 重载服务(30s 超时)。经 a.execCmd 注入缝。
//
// F2 审查修复:reload 服务名必须 ∈ policy 的 ReloadServices 白名单
// (app.reloadSvcs),拒绝任意服务名(防 agent 经蓝图 reload 任意 systemd 单元)。
func runReload(ctx context.Context, a *app, svc string) error {
	if !containsStr(a.reloadSvcs, svc) {
		return fmt.Errorf("reload 服务 %q 不在白名单", svc)
	}
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := a.execCmd(runCtx, "systemctl", "restart", svc); err != nil {
		return err
	}
	return nil
}

// containsStr 报告 s 是否在 ss 中(小切片线性扫描,与 shellpolicy stringSet 同风格)。
func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// validateOutputPathResolved 是符号链接逃逸门(F1/F2 复审 4b 修复)。
//
// validateOutputPath 只做词法前缀校验——若 outputDirs 下存在指向白名单外
// (如 /etc/shadow 所在目录)的符号链接,词法通过但真实写入落到白名单外。
// 本函数把目标文件的**父目录**解析为真实路径(EvalSymlinks),再校验解析
// 结果是否仍落在某个 outputDir 的解析路径前缀内;不通过即拒绝。
//
// 目标文件本身可能尚未存在(apply 前),故解析父目录而非文件本身。
func validateOutputPathResolved(outputDirs []string, target string) error {
	realParent, err := filepath.EvalSymlinks(filepath.Dir(target))
	if err != nil {
		return fmt.Errorf("解析目标目录符号链接失败: %w", err)
	}
	for _, dir := range outputDirs {
		realDir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue // 该白名单目录本身可能尚不存在,跳过
		}
		if realParent == realDir || strings.HasPrefix(realParent, realDir+"/") {
			return nil
		}
	}
	return fmt.Errorf("目标目录 %q 解析为 %q,越出允许目录白名单(符号链接逃逸被拒)", target, realParent)
}

// writeBlueprintAudit 追加一条蓝图工具审计条目(尽力而为:写失败静默忽略,
// 与 daedalus-tx 的 hostAudit 同纪律)。args 绝不含渲染内容/secret 明文。
func writeBlueprintAudit(tool string, args map[string]any, outcome string) {
	data, err := json.Marshal(args)
	if err != nil {
		return
	}
	v, err := audit.ParseValue(string(data))
	if err != nil {
		v = audit.NewString(string(data))
	}
	_, _ = audit.LogAudit(audit.Entry{
		Identity: blueprintIdentity,
		Tool:     tool,
		Args:     v,
		Outcome:  outcome,
	})
}
