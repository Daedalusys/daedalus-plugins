package main

// list_tools.go —— blueprint_list / blueprint_inspect 两个只读工具:list 遍历
// 注册表返回摘要切片;inspect 返回单个蓝图详情。都不碰 plan store、不写状态。

import (
	"context"
	"encoding/json"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type blueprintSummary struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Version     string `json:"version"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

type blueprintDetail struct {
	ID                 string   `json:"id"`
	DisplayName        string   `json:"display_name"`
	Version            string   `json:"version"`
	Description        string   `json:"description"`
	Category           string   `json:"category"`
	OutputPathTemplate string   `json:"output_path_template"`
	ReloadService      string   `json:"reload_service"`
	RequiredTools      []string `json:"required_tools"`
	Schema             any      `json:"schema"` // schema.json 原文(解析为 JSON 对象)
	TemplatePreview    string   `json:"template_preview"`
	PostCheckPreview   string   `json:"post_check_preview"`
	ReadmeSummary      string   `json:"readme_summary"`
}

func registerListTool(server *mcp.Server, a *app) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blueprint_list",
		Description: "列出全部可用蓝图(只读摘要:id / display_name / version / category / description)。",
		InputSchema: &jsonschema.Schema{
			Type:       "object",
			Properties: map[string]*jsonschema.Schema{},
		},
		Annotations: readOnlyAnnotations(),
	}, handleList(a))
}

func registerInspectTool(server *mcp.Server, a *app) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "blueprint_inspect",
		Description: "查看单个蓝图完整详情(schema / template 预览 / README 摘要 / required_tools / output_path_template / reload_service)。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"name": {Type: "string", Description: "蓝图 id,如 nginx-vhost。"},
			},
			Required: []string{"name"},
		},
		Annotations: readOnlyAnnotations(),
	}, handleInspect(a))
}

// listIn 是 blueprint_list 的输入(In 类型为 map 以满足 object 约束)。
type listIn map[string]any

func handleList(a *app) func(context.Context, *mcp.CallToolRequest, listIn) (*mcp.CallToolResult, any, error) {
	return func(_ context.Context, _ *mcp.CallToolRequest, _ listIn) (*mcp.CallToolResult, any, error) {
		summaries := make([]blueprintSummary, 0, len(a.reg.orderedIDs()))
		for _, id := range a.reg.orderedIDs() {
			cb := a.reg.byID[id]
			b := cb.Blueprint
			summaries = append(summaries, blueprintSummary{
				ID:          b.ID,
				DisplayName: b.DisplayName,
				Version:     b.Version,
				Category:    b.Category,
				Description: b.Description,
			})
		}
		return jsonResult(summaries), nil, nil
	}
}

type inspectIn struct {
	Name string `json:"name" jsonschema:"蓝图 id。"`
}

func handleInspect(a *app) func(context.Context, *mcp.CallToolRequest, inspectIn) (*mcp.CallToolResult, any, error) {
	return func(_ context.Context, _ *mcp.CallToolRequest, in inspectIn) (*mcp.CallToolResult, any, error) {
		cb, ok := a.reg.get(in.Name)
		if !ok {
			return toolErrorf("blueprint %q 不存在", in.Name), nil, nil
		}
		b := cb.Blueprint
		detail := blueprintDetail{
			ID:                 b.ID,
			DisplayName:        b.DisplayName,
			Version:            b.Version,
			Description:        b.Description,
			Category:           b.Category,
			OutputPathTemplate: b.OutputPathTmpl,
			ReloadService:      b.ReloadService,
			RequiredTools:      b.RequiredTools,
			TemplatePreview:    cb.templateRaw,
			PostCheckPreview:   cb.postCheckCmd,
			ReadmeSummary:      cb.readmeSummary,
		}
		if len(cb.schemaRaw) > 0 {
			var s any
			if err := json.Unmarshal(cb.schemaRaw, &s); err == nil {
				detail.Schema = s
			}
		}
		return jsonResult(detail), nil, nil
	}
}
