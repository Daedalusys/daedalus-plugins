package main

// apply_tool.go —— blueprint_apply 工具。
//
// 流程:
//  1. plan store 按 plan_id 取 plan;不存在即拒;
//  2. plan.Name 与入参 name 一致性校验(防串用);
//  3. confirm_token 校验(VerifyConfirmToken,成功即消费,单次有效);
//  4. 目标路径再次校验 ∈ outputDirs(纵深防御,防 plan store 被篡改);
//  5. 读旧文件快照 → 写入渲染结果(0o644);
//  6. post_check:把 cb.postCheckCmd 脚本写临时文件 → sh <tmp> argv 直发,
//     30s 超时;stdout/stderr 不进 audit(防 secret 泄漏);
//  7. reload:systemctl restart <ReloadService>,30s 超时;
//  8. 失败逆序回滚:post_check 或 reload 失败 → 有旧文件恢复旧内容,否则删新文件;
//  9. audit 写条目(经 recordAudit 在 handleApply 这一唯一 choke point 落链:
//     每次调用恰一条,九道拒绝门各记 denied、执行故障记 error、完成记 success;
//     tool="blueprint_apply", args 不含渲染内容与令牌值);
// 10. 返回 ApplyResult(tx_id="(v1-direct)",applied_at,config_path,post_check_ok,reload_ok)。
//
// 执行模型 v1-direct:不经 daedalus-tx 子命令链;post_check / reload 两个子进程
// 调用统一经 a.execCmd 注入缝,测试替换为假实现避免真实系统调用。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/blueprint"
	"github.com/Daedalusys/daedalus-sdk/shellpolicy"
)

type applyIn struct {
	Name         string `json:"name" jsonschema:"蓝图 id,如 nginx-vhost。"`
	PlanID       string `json:"plan_id" jsonschema:"blueprint_render 返回的 plan_id。"`
	ConfirmToken string `json:"confirm_token" jsonschema:"blueprint_render 返回的单次有效确认令牌。"`
}

type applyOut struct {
	TxID        string `json:"tx_id"`
	AppliedAt   string `json:"applied_at"`
	ConfigPath  string `json:"config_path"`
	PostCheckOK bool   `json:"post_check_ok"`
	ReloadOK    bool   `json:"reload_ok"`
	// RemoveToken 是后续 blueprint_remove 需出示的单次令牌;必须回传客户端,否则 remove 永不可达。
	RemoveToken string `json:"remove_token"`
}

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

// handleApply 是 blueprint_apply 的审计 choke point:把判定逻辑交给
// applyResult,自己只负责"每次调用恰记一条链"。审计写在最后一步之外——
// 拒绝路径(plan/令牌/白名单任一关)同样是操作员需要回看的轨迹,漏记即
// 等于给 agent 留了一条无痕试错通道。args 只带 name / plan_id / 成功或
// 落盘后的 target,confirm_token 值与渲染内容(可能含 secret 引用)严禁进链。
func handleApply(a *app) func(context.Context, *mcp.CallToolRequest, applyIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in applyIn) (*mcp.CallToolResult, any, error) {
		res, target, outcome, cause := applyResult(ctx, a, in)
		args := map[string]any{"name": in.Name, "plan_id": in.PlanID}
		if target != "" {
			args["target"] = target
		}
		recordAudit("blueprint_apply", outcome, args, cause)
		return res, nil, nil
	}
}

// applyResult 判定一次 apply 的结局,返回 (工具结果, 已进入落盘流程的目标路径,
// 结局 token, 失败因)。拒绝门一律 denied,写盘/post_check/reload/回滚故障为 error。
func applyResult(ctx context.Context, a *app, in applyIn) (*mcp.CallToolResult, string, string, error) {
	plan, ok := a.plans.get(in.PlanID)
	if !ok {
		err := fmt.Errorf("plan %q 不存在(先 blueprint_render)", in.PlanID)
		return toolError(err), "", "denied", err
	}

	// 防串用:name 必须与 plan 记录的蓝图一致。
	if plan.Name != in.Name {
		err := fmt.Errorf("plan %q 属于蓝图 %q,与入参 %q 不匹配", in.PlanID, plan.Name, in.Name)
		return toolError(err), "", "denied", err
	}

	// confirm_token 校验(成功即消费,单次有效)。先比对用户提供的 token 与
	// plan store 中 render 生成的真实 token(VerifyConfirmToken 只校验"非空/
	// plan_id 匹配/未消费/未过期",不持有真实 token——配对语义必须由调用方先
	// 比对 token 串)。
	if plan.Token.Token == "" {
		err := fmt.Errorf("plan %q 无关联确认令牌(render 异常)", in.PlanID)
		return toolError(err), "", "denied", err
	}
	if in.ConfirmToken != plan.Token.Token {
		err := fmt.Errorf("confirm_token 与 plan %q 不匹配", in.PlanID)
		return toolError(err), "", "denied", err
	}
	if err := blueprint.VerifyConfirmToken(in.PlanID, blueprint.ConfirmToken{
		Token:   in.ConfirmToken,
		PlanID:  in.PlanID,
		Expires: plan.Token.Expires,
	}); err != nil {
		return toolError(err), "", "denied", err
	}

	// 目标路径白名单(纵深防御,防 plan store 被篡改)。除词法前缀外,必须
	// 解析符号链接确认真实路径仍在白名单内——否则 outputDirs 下若有指向
	// /etc/shadow 等敏感文件的 symlink,词法校验通过但写入实际落到白名单外。
	if !validateOutputPath(a.outputDirs, plan.Target) {
		err := fmt.Errorf("目标路径 %q 越出允许目录白名单", plan.Target)
		return toolError(err), "", "denied", err
	}
	if err := validateOutputPathResolved(a.outputDirs, plan.Target); err != nil {
		return toolError(err), "", "denied", err
	}

	cb, ok := a.reg.get(in.Name)
	if !ok {
		err := fmt.Errorf("blueprint %q 不存在", in.Name)
		return toolError(err), "", "denied", err
	}

	hadOld := false
	var oldContent []byte
	if data, err := os.ReadFile(plan.Target); err == nil {
		hadOld = true
		oldContent = data
	}
	if err := os.MkdirAll(filepath.Dir(plan.Target), 0o755); err != nil {
		return toolErrorf("创建目标目录失败: %v", err), plan.Target, "error", err
	}
	if err := os.WriteFile(plan.Target, []byte(plan.Rendered), 0o644); err != nil {
		return toolErrorf("写入配置失败: %v", err), plan.Target, "error", err
	}

	// rollback 闭包:失败时恢复旧快照或删除新文件。回滚本身的错误不能被
	// `_ =` 吞掉——回滚失败必须回传给调用方,否则"配置已破坏但回滚也失败"
	// 的灾难状态会静默通过。
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

	// post_check(脚本非空才执行)。params 经 plan.Params 传入,行内 {param}
	// 占位符渲染;argv 直发(无 shell 求值)。
	if cb.postCheckCmd != "" {
		if err := runPostCheck(ctx, a, cb.postCheckCmd, plan.Params); err != nil {
			rollback()
			if rollbackErr != nil {
				wrapped := fmt.Errorf("post_check 失败(已回滚): %v; 回滚错误: %v", err, rollbackErr)
				return toolError(wrapped), plan.Target, "error", wrapped
			}
			return toolErrorf("post_check 失败(已回滚): %v", err), plan.Target, "error", err
		}
	}

	if err := runReload(ctx, a, cb.Blueprint.ReloadService); err != nil {
		rollback()
		if rollbackErr != nil {
			wrapped := fmt.Errorf("reload 失败(已回滚): %v; 回滚错误: %v", err, rollbackErr)
			return toolError(wrapped), plan.Target, "error", wrapped
		}
		return toolErrorf("reload 失败(已回滚): %v", err), plan.Target, "error", err
	}

	// 成功:为该 plan 生成 remove 确认令牌并回写 plan store(apply 是 remove
	// 令牌的唯一生产点;remove 校验时比对 store 中的 RemoveToken),并同步
	// 置位 Applied 标志供 handleRemove 判断"已应用"。
	plan.RemoveToken = blueprint.GenerateConfirmToken("remove:" + in.Name)
	plan.Applied = true
	a.plans.put(in.PlanID, plan)

	out := applyOut{
		TxID:        "(v1-direct)",
		AppliedAt:   time.Now().UTC().Format(time.RFC3339),
		ConfigPath:  plan.Target,
		PostCheckOK: true,
		ReloadOK:    true,
		RemoveToken: plan.RemoveToken.Token,
	}
	res := jsonResult(out)
	if res.IsError {
		return res, plan.Target, "error", fmt.Errorf("序列化 apply 结果失败")
	}
	return res, plan.Target, "success", nil
}

// runPostCheck 执行蓝图 post_check 命令序列。
//
// post_check 不经任何 shell 解释器:静态扫描无法穷尽 shell 语义,`evil=$(whoami);
// $evil` 与 `sudo whoami` 等变量间接/提权路径仍可绕过。改为**逐行 argv 直发**:
//
//   - 每行 = 一条命令,首个 token 为命令名,必须 ∈ PostCheckAllowCommands,
//     白名单外即整体拒绝;
//   - 每行经 quoteSplit 引号感知分词,**先分词、后逐 token 渲染 `{param}` 占位符**,
//     再整行 argv 直发(execCmd)。顺序至关重要:若先替换后分词,含空格的参数值
//     (如 domain = "a b")会被切成多个 argv token,等效于参数注入;逐 token 替换
//     保证一个值永远只落在它所属的那一个 token 内。变量展开/命令替换/管道/
//     重定向/sudo 提权仍然全部不可能发生;
//   - 白名单校验在**替换后**的 argv[0] 上进行(防参数值把命令名本身改掉);
//   - `#` 注释行与空行跳过;任一命令非零退出即整体失败;
//   - 副作用:能力从"任意 shell"收敛为"白名单命令序列"——安全边界要求的取舍。
func runPostCheck(ctx context.Context, a *app, script string, params map[string]any) error {
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		argv, err := quoteSplit(line)
		if err != nil {
			return fmt.Errorf("post_check 行解析失败 %q: %w", line, err)
		}
		for i, tok := range argv {
			argv[i] = renderPostCheckToken(tok, params)
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

// renderPostCheckToken 把单个 argv token 内的 `{param}` 占位符替换为 params
// 值(与 output_path_template 同约定);缺失参数不替换(保留字面量,避免命令
// 语义被静默改变)。替换发生在分词之后,值中的空格不会诞生新 token。
func renderPostCheckToken(tok string, params map[string]any) string {
	for k, v := range params {
		s, ok := v.(string)
		if !ok {
			continue
		}
		tok = strings.ReplaceAll(tok, "{"+k+"}", s)
	}
	return tok
}

// quoteSplit 做引号感知的 argv 分词(不经 shell):按空白切分为 argv 元素,
// 双引号 `"..."` / 单引号内的内容整体作为一个元素,不做任何转义或展开。
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

// runReload 经 systemctl restart 重载服务(30s 超时),走 a.execCmd 注入缝。
// reload 服务名必须 ∈ policy 的 ReloadServices 白名单(app.reloadSvcs),拒绝
// 任意服务名(防 agent 经蓝图 reload 任意 systemd 单元)。
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

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// validateOutputPathResolved 是符号链接逃逸门,同时把关目录与目标文件本身:
//
// validateOutputPath 只做词法前缀校验——若 outputDirs 下存在指向白名单外
// (如 /etc/shadow 所在目录)的符号链接,词法通过但真实写入落到白名单外。
// 本函数把目标文件的**父目录**解析为真实路径(EvalSymlinks),再校验解析
// 结果是否仍落在某个 outputDir 的解析路径前缀内;不通过即拒绝。
//
// 目标文件本身可能尚未存在(apply 前),故解析父目录而非文件本身;但**已
// 存在**时必须 Lstat 检查其本身:父目录干净不代表文件不是指向白名单外
// 的符号链接——os.WriteFile 会跟随符号链接写入,删除时 os.Remove 也只会
// 摘除链接而留下真实目标。故符号链接目标一律拒绝跟随。
func validateOutputPathResolved(outputDirs []string, target string) error {
	if fi, err := os.Lstat(target); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("目标文件 %q 本身为符号链接,拒绝跟随(防写入/删除落到白名单外)", target)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("检查目标文件符号链接失败: %w", err)
	}
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
