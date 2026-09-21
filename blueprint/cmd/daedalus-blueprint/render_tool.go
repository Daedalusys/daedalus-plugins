package main

// render_tool.go —— blueprint_render 工具(todo 18)。
//
// 流程(与任务规格逐条对应):
//  1. schema 校验:params JSON 反序列化为 map[string]any,经预编译的
//     schemaResolved 校验(Unmarshal → Resolve → Validate);缺必填/类型错/
//     未知字段(reason:additionalProperties:false)即拒绝;
//  2. 明文 secret 检测:遍历 params 值,以 secret:// 开头的引用经
//     blueprint.ValidateSecretRef 校验格式;**非 secret:// 的 password 类
//     字段值** → warning 且拒绝(明文绝不进渲染结果/审计);
//  3. 渲染路径模板:OutputPathTmpl 的 {param} 用 params 替换;
//  4. 目标路径 ⊆ policy.Blueprints.OutputDirs 前缀(pathguard 风格段边界);
//  5. 渲染配置模板:Go text/template,Option("missingkey=error"),渲染前先
//     fillTemplateData 把 schema default 补齐进数据(使"未显式传参"与
//     "显式传默认值"在模板视角等价);
//  6. diff:目标文件已存在则算行级 diff,否则空;
//  7. plan_id(16 hex 随机串)+ GenerateConfirmToken(planID);
//  8. 返回 RenderResult{plan_id, rendered_content, diff, warnings, confirm_token}
//     并把 plan 存入进程内 plan store 供 apply/status 取用。
//
// nginx `$var` 隐患的处理方案(见 learnings):Go text/template 只用 `{{…}}`
// 识别动作,`$host` / `$remote_addr` / `$proxy_add_x_forwarded_for` 与
// postgres 的 `$$` dollar-quoting、`$1` 反向引用**都不被当作变量**,实测
// missingkey=error 下渲染原文原样保留——故渲染层**无需任何 `$` 转义**,
// 直接把模板原文交给 Parse 即可(已验证,见 task 18 render 测试断言)。

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
)

// renderIn 是 blueprint_render 的输入。
type renderIn struct {
	Name   string `json:"name" jsonschema:"蓝图 id。"`
	Params any    `json:"params" jsonschema:"蓝图参数对象(键与 schema.json 字段对应)。"`
}

// renderOut 是 blueprint_render 的输出(extends blueprint.RenderResult 外加
// confirm_token)。
type renderOut struct {
	PlanID          string   `json:"plan_id"`
	RenderedContent string   `json:"rendered_content"`
	Diff            string   `json:"diff"`
	Warnings        []string `json:"warnings"`
	TargetPath      string   `json:"target_path"`
	ConfirmToken    string   `json:"confirm_token"`
}

// registerRenderTool 注册 blueprint_render(只读:仅生成 plan,不写盘)。
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

// handleRender 返回 renderIn handler 闭包。
func handleRender(a *app) func(context.Context, *mcp.CallToolRequest, renderIn) (*mcp.CallToolResult, any, error) {
	return func(_ context.Context, _ *mcp.CallToolRequest, in renderIn) (*mcp.CallToolResult, any, error) {
		cb, ok := a.reg.get(in.Name)
		if !ok {
			return toolErrorf("blueprint %q 不存在", in.Name), nil, nil
		}
		// 归一化 params 为 map[string]any(客户端可能传结构化对象)。
		params, err := normalizeParams(in.Params)
		if err != nil {
			return toolErrorf("params 解析失败: %v", err), nil, nil
		}

		// ① 明文 secret 检测(fail-closed,先于 schema:安全语义错误优先于
		// 格式细节错误,且明文密码即便侥幸过 schema pattern 也必须在此被拒)。
		if err := detectPlaintextSecrets(params); err != nil {
			return toolError(err), nil, nil
		}

		// ② schema 校验(缺必填/类型错/未知字段)。
		if cb.schemaResolved != nil {
			if err := cb.schemaResolved.Validate(params); err != nil {
				return toolErrorf("params 校验失败: %v", err), nil, nil
			}
		}

		// 渲染数据:schema default 补齐(使模板对含默认值字段的访问成立)。
		data := fillTemplateData(cb.schemaResolved, params)

		// ③ 路径模板 {param} 替换 + ④ 越界校验。
		target, err := renderPath(cb.Blueprint.OutputPathTmpl, data)
		if err != nil {
			return toolError(err), nil, nil
		}
		if !validateOutputPath(a.outputDirs, target) {
			return toolErrorf("目标路径 %q 越出允许目录白名单 (%s)", target, strings.Join(a.outputDirs, ", ")), nil, nil
		}

		// ⑤ 渲染配置模板(missingkey=error,严格)。
		var buf bytes.Buffer
		if err := cb.template.Execute(&buf, data); err != nil {
			return toolErrorf("模板渲染失败: %v", err), nil, nil
		}
		rendered := buf.String()

		// ⑥ diff:目标已存在则算行级 diff,否则空。
		diff := ""
		if existing, err := os.ReadFile(target); err == nil {
			diff = lineDiff(string(existing), rendered)
		}

		// ⑦ plan_id + confirm token。
		planID := newPlanID()
		tok := blueprint.GenerateConfirmToken(planID)

		// 落进程内 plan store(供 apply/status 取用)。
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
		return jsonResult(out), nil, nil
	}
}

// normalizeParams 把任意 JSON 输入归一化为 map[string]any。
//
// params 以 any 接收(客户端可能传 map 也可能是 json.RawMessage 经 SDK 解码
// 成 map),此处统一经 JSON round-trip 归一化,并强制为对象形态(参数必须
// 是键值对,不接受数组/标量)。
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
//   - 键名属 password 类(password/secret/token/key/passwd/pwd/credential)
//     且值为非 secret:// 开头的字符串 → 拒绝(明文 warning 语义)。
//
// 明文绝不进入渲染结果与审计参数;引用(secret:// 原文)允许透传(真值
// 解析推迟到 apply,且 apply 侧同样不把明文写进 audit)。
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

// isPasswordClassKey 判定字段名是否属 password 类(触发明文检测)。
func isPasswordClassKey(k string) bool {
	lk := strings.ToLower(k)
	for _, kw := range []string{"password", "passwd", "pwd", "secret", "token", "key", "credential"} {
		if strings.Contains(lk, kw) {
			return true
		}
	}
	return false
}

// renderPath 把 OutputPathTmpl 的 {param} 占位符用 data 替换。
//
// 替换后残留的 "{" 占位(有占位符但 data 缺对应键)→ error(fail-closed:
// 路径模板引用了不存在的参数,属于数据/模板缺陷,绝不生成不可靠路径)。
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
