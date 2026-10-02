// Command daedalus-search 是 Baloo 文件/内容只读 MCP 服务器(stdio JSON-RPC)。
// 提供 3 个工具:search_files / search_content / search_reindex;前 2 个走
// Baloo 索引(D-Bus 探测 + baloosearch fork),search_reindex 恒返回
// started=false(L1 deferred)。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/version"
)

const serverName = "daedalus-search"

// --- JSON schema ---

// intPtr 返回 int 指针(用于 jsonschema 数值约束)。
func intPtr(v int) *int { return &v }

// float64Ptr 返回 float64 指针(用于 jsonschema 数值约束)。
func float64Ptr(v float64) *float64 { return &v }

// searchFilesSchema 是 search_files 的入参。
var searchFilesSchema = &jsonschema.Schema{
	Type:     "object",
	Required: []string{"query"},
	Properties: map[string]*jsonschema.Schema{
		"query": {
			Type:        "string",
			MinLength:   intPtr(1),
			Description: "Baloo 查询语言;透传 `content:` / `filename:` 等元字符。",
		},
		"dir": {
			Type:        "string",
			Pattern:     searchDirPatternString,
			Description: "可选绝对路径,词法合法;限定查询在该目录树内。",
		},
		"mimetype": {
			Type:        "string",
			Description: "可选 `type/subtype`(经 mime.ParseMediaType 严格校验)。",
		},
		"since": {
			Type:        "string",
			Description: "可选 RFC3339 时间戳;低于此日期的文件被排除(客户端二次过滤)。",
		},
		"until": {
			Type:        "string",
			Description: "可选 RFC3339 时间戳;高于此日期的文件被排除(客户端二次过滤)。",
		},
		"size_min": {
			Type:        "integer",
			Minimum:     float64Ptr(0),
			Description: "可选最小字节数(>=0)。",
		},
		"size_max": {
			Type:        "integer",
			Minimum:     float64Ptr(0),
			Description: "可选最大字节数(>=0)。",
		},
	},
}

// searchContentSchema 是 search_content 的入参。
var searchContentSchema = &jsonschema.Schema{
	Type:     "object",
	Required: []string{"query"},
	Properties: map[string]*jsonschema.Schema{
		"query": searchFilesSchema.Properties["query"],
		"dir":   searchFilesSchema.Properties["dir"],
	},
}

// reindexSchema 是 search_reindex 的入参。dir 可选,词法合法。
var reindexSchema = &jsonschema.Schema{
	Type: "object",
	Properties: map[string]*jsonschema.Schema{
		"dir": searchFilesSchema.Properties["dir"],
	},
}

// --- main + helpers ---

func main() {
	server := newServer(newService())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !isCleanShutdown(err) {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}
}

// isCleanShutdown 判定"正常结束":stdin 客户端断开(context.Canceled / EOF)
// 与 SDK 内部 jsonrpc2.ErrServerClosing("server is closing: ...");后者位于
// internal 包无法用 errors.Is 匹配,按消息前缀归类。
func isCleanShutdown(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return true
	}
	return strings.HasPrefix(err.Error(), "server is closing")
}

// newServer 注册 3 个工具并返回 *mcp.Server。
func newServer(svc *service) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	// 3 工具皆为只读:L0 file search + L1 占位。
	nonDestructive := false
	closedWorld := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "search_files",
		Description: "只读文件搜索,基于 KDE Baloo 索引。会话 bus 上的 org.kde.baloo 不可达或 baloosearch 缺失时降级为空集 + note,不报错。参数形态:query(必填)、dir(可选绝对路径)、mimetype(可选 type/subtype)、since/until(可选 RFC3339)、size_min/size_max(可选字节数)。返回 {files:[{url,path,mimetype,size,mtime,rating}], count, note}。",
		InputSchema: searchFilesSchema,
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
		in := SearchFileArgs{Query: stringArg(args, "query")}
		if v, ok := args["dir"].(string); ok {
			in.Dir = v
		}
		if v, ok := args["mimetype"].(string); ok {
			in.Mimetype = v
		}
		if v, ok := args["since"].(string); ok {
			in.Since = v
		}
		if v, ok := args["until"].(string); ok {
			in.Until = v
		}
		if v, ok := args["size_min"]; ok {
			if n, ok := int64Arg(v); ok {
				in.SizeMin = &n
			}
		}
		if v, ok := args["size_max"]; ok {
			if n, ok := int64Arg(v); ok {
				in.SizeMax = &n
			}
		}
		res, err := svc.SearchFiles(ctx, in)
		if err != nil {
			return raisedError("search_files", err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "search_content",
		Description: "只读全文内容搜索,基于 Baloo 索引(需 Baloo 启用内容索引)。参数形态:query(必填,透传 Baloo 查询语言,支持 `content:` 前缀)、dir(可选绝对路径)。返回 {files:[{url,path}], count, note};Baloo 不可达或索引未启用时降级为空集 + note。",
		InputSchema: searchContentSchema,
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
		in := ContentSearchArgs{Query: stringArg(args, "query")}
		if v, ok := args["dir"].(string); ok {
			in.Dir = v
		}
		res, err := svc.SearchContent(ctx, in)
		if err != nil {
			return raisedError("search_content", err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "search_reindex",
		Description: "重建 Baloo 索引占位。L1 deferred:本工具**不调用 daedalus-tx**、**不触发 baloosearch/balooctl**、**不改任何系统状态**;恒返回 started=false + 说明 note。Baloo 不可达时额外提示。调用方**不应**假定索引已重建。参数:dir(可选绝对路径,仅回显)。",
		InputSchema: reindexSchema,
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
		in := ReindexArgs{}
		if v, ok := args["dir"].(string); ok {
			in.Dir = v
		}
		res, err := svc.Reindex(ctx, in)
		if err != nil {
			return raisedError("search_reindex", err), nil, nil
		}
		return jsonResult(res), nil, nil
	})

	return server
}

// stringArg 取 args[key] 的字符串值;缺为 ""。
func stringArg(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

// int64Arg 把 MCP 入参 JSON 数值转 int64(支持 float64 / int / int64);失败返 (0,false)。
func int64Arg(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

// jsonResult 对应 Python FastMCP 的 json.dumps(..., ensure_ascii=False,
// indent=2);Go 端用 SetEscapeHTML(false) + SetIndent("  ") 等价实现。
func jsonResult(v any) *mcp.CallToolResult {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return raisedError("jsonResult", err)
	}
	return textResult(strings.TrimSuffix(b.String(), "\n"))
}

// textResult 构造成功结果(单文本块)。
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// raisedError 构造 isError=true 的工具错误结果,文本形态与 FastMCP 未捕获
// 异常转换一致:"Error executing tool <name>: <消息>"。
func raisedError(tool string, err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error executing tool %s: %v", tool, err)}},
		IsError: true,
	}
}
