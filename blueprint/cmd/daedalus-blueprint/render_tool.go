package main

// render_tool.go —— blueprint_render 工具。
//
// 流程:schema 校验 → 明文 secret 检测 → 路径模板 {param} 替换 → 目标路径
// 越界校验 → 配置模板渲染(missingkey=error)→ 行级 diff → plan_id +
// confirm_token → 返回并把 plan 存入进程内 plan store 供 apply/status 取用。
// 每次调用在 handleRender choke point 落恰一条审计(只记入参摘要,渲染内容
// 与参数值不进链)。
//
// nginx `$var` 隐患:Go text/template 只用 `{{…}}` 识别动作,`$host` 与 postgres
// 的 `$$` dollar-quoting、`$1` 反向引用都不被当作变量,missingkey=error 下原文
// 原样保留——故渲染层无需任何 `$` 转义。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/blueprint"
	"github.com/Daedalusys/daedalus-sdk/confirmation"
)

type renderIn struct {
	Name   string `json:"name" jsonschema:"蓝图 id。"`
	Params any    `json:"params" jsonschema:"蓝图参数对象(键与 schema.json 字段对应)。"`
}

type renderOut struct {
	PlanID          string   `json:"plan_id"`
	RenderedContent string   `json:"rendered_content"`
	Diff            string   `json:"diff"`
	Warnings        []string `json:"warnings"`
	TargetPath      string   `json:"target_path"`
	ConfirmToken    string   `json:"confirm_token"`
}

func registerRenderTool(server *mcp.Server, a *app) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blueprint_render",
		Description: "渲染蓝图参数为配置文件文本并预览差异。不写盘，返回 plan_id + rendered_content + diff + confirm_token 供后续 blueprint_apply 引用。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"name": {Type: "string", Description: "蓝图 id,如 nginx-vhost。"},
				"params": {
					Type:        "object",
					Description: "蓝图参数对象(键与对应 schema.json 字段一致)。",
				},
			},
			Required: []string{"name", "params"},
		},
		Annotations: readOnlyAnnotations(),
	}, handleRender(a))
}

// handleRender 是 blueprint_render 的审计 choke point:args 只记录入参摘要
// (name,成功时补 plan_id 与"需确认令牌"事实),渲染内容与参数值——可能
// 内嵌 secret:// 引用或敏感输入——一律严禁进链。入参 / schema / 白名单 /
// 模板校验拒绝记 denied,序列化故障记 error,其余 success。
func handleRender(a *app) func(context.Context, *mcp.CallToolRequest, renderIn) (*mcp.CallToolResult, any, error) {
	return func(_ context.Context, _ *mcp.CallToolRequest, in renderIn) (*mcp.CallToolResult, any, error) {
		res, planID, outcome, cause := renderResult(a, in)
		args := map[string]any{"name": in.Name}
		if planID != "" {
			args["plan_id"] = planID
			args["confirm_required"] = true
		}
		recordAudit("blueprint_render", outcome, args, cause)
		return res, nil, nil
	}
}

func renderResult(a *app, in renderIn) (*mcp.CallToolResult, string, string, error) {
	cb, ok := a.reg.get(in.Name)
	if !ok {
		err := fmt.Errorf("blueprint %q 不存在", in.Name)
		return toolError(err), "", "denied", err
	}
	params, err := normalizeParams(in.Params)
	if err != nil {
		return toolErrorf("params 解析失败: %v", err), "", "denied", err
	}

	// 明文 secret 检测(fail-closed,先于 schema:安全语义错误优先于
	// 格式细节错误,且明文密码即便侥幸过 schema pattern 也必须在此被拒)。
	if err := detectPlaintextSecrets(params); err != nil {
		return toolError(err), "", "denied", err
	}

	if cb.schemaResolved != nil {
		if err := cb.schemaResolved.Validate(params); err != nil {
			return toolErrorf("params 校验失败: %v", err), "", "denied", err
		}
	}

	data := fillTemplateData(cb.schemaResolved, params)

	target, err := renderPath(cb.Blueprint.OutputPathTmpl, data)
	if err != nil {
		return toolError(err), "", "denied", err
	}
	if !validateOutputPath(a.outputDirs, target) {
		err := fmt.Errorf("目标路径 %q 越出允许目录白名单 (%s)", target, strings.Join(a.outputDirs, ", "))
		return toolError(err), "", "denied", err
	}

	var buf bytes.Buffer
	if err := cb.template.Execute(&buf, data); err != nil {
		return toolErrorf("模板渲染失败: %v", err), "", "denied", err
	}
	rendered := buf.String()

	diff := ""
	if existing, err := os.ReadFile(target); err == nil {
		diff = lineDiff(string(existing), rendered)
	}

	planID := newPlanID()
	tok := confirmation.GenerateConfirmToken(planID)

	a.plans.put(planID, renderedPlan{
		Name:     in.Name,
		Params:   data,
		Rendered: rendered,
		Target:   target,
		Token:    tok,
	})

	out := renderOut{
		PlanID:          planID,
		RenderedContent: rendered,
		Diff:            diff,
		Warnings:        nil,
		TargetPath:      target,
		ConfirmToken:    tok.Token,
	}
	res := jsonResult(out)
	if res.IsError {
		return res, "", "error", nil
	}
	return res, planID, "success", nil
}

// normalizeParams 把任意 JSON 输入归一化为 map[string]any:params 以 any 接收,
// 此处统一经 JSON round-trip 归一化并强制为对象形态(不接受数组/标量)。
func normalizeParams(v any) (map[string]any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("序列化失败: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("params 必须是 JSON 对象: %w", err)
	}
	return m, nil
}

// detectPlaintextSecrets 遍历 params,拒绝明文 secret:
//   - 值以 secret:// 开头 → blueprint.ValidateSecretRef 校验格式;
//   - 键名属 password 类且值为非 secret:// 开头的字符串 → 拒绝。
//
// 明文绝不进入渲染结果与审计参数;secret:// 引用允许透传(真值解析推迟到
// apply,且 apply 侧同样不把明文写进 audit)。
func detectPlaintextSecrets(params map[string]any) error {
	var problems []string
	for k, v := range params {
		s, isStr := v.(string)
		if !isStr {
			continue
		}
		if strings.HasPrefix(s, "secret://") {
			if err := blueprint.ValidateSecretRef(s); err != nil {
				return err // 畸形引用本身即错误(格式防线)。
			}
			continue
		}
		if isPasswordClassKey(k) {
			problems = append(problems, fmt.Sprintf("字段 %q 提供了明文值(仅接受 secret:// 引用,明文拒绝)", k))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("明文 secret 被拒绝: %s", strings.Join(problems, "; "))
	}
	return nil
}

func isPasswordClassKey(k string) bool {
	lk := strings.ToLower(k)
	for _, kw := range []string{"password", "passwd", "pwd", "secret", "token", "key", "credential"} {
		if strings.Contains(lk, kw) {
			return true
		}
	}
	return false
}

// renderPath 把 OutputPathTmpl 的 {param} 占位符用 data 替换;替换后残留的 "{"
// 占位(模板引用了不存在的参数)→ error(fail-closed:绝不生成不可靠路径)。
func renderPath(tmpl string, data map[string]any) (string, error) {
	out := tmpl
	for {
		start := strings.IndexByte(out, '{')
		if start < 0 {
			break
		}
		end := strings.IndexByte(out[start+1:], '}')
		if end < 0 {
			return "", fmt.Errorf("路径模板含未闭合占位符: %q", tmpl)
		}
		end += start + 1
		name := out[start+1 : end]
		if name == "" {
			return "", fmt.Errorf("路径模板含空占位符: %q", tmpl)
		}
		val, ok := data[name]
		if !ok {
			return "", fmt.Errorf("路径模板占位符 {%s} 无对应参数", name)
		}
		out = out[:start] + fmt.Sprintf("%v", val) + out[end+1:]
	}
	return out, nil
}
