// Command daedalus-snapshot 是快照能力 MCP 服务器(stdio JSON-RPC,只读)。
//
// 提供 2 个工具(snapshot_backends / snapshot_list):前者回答"本机有哪些快照
// 后端工具就位且能自报版本",后者只读列举现有快照。绝不创建、删除或回滚快照:
// 任何变更都属 daedalus-tx 的职责,本插件只陈述事实。
//
// 探测走固定绝对路径候选表而非 PATH 搜索(宿主 PATH 不可控,且候选路径必须能
// 在 manifest 的 permissions.run 里逐条声明);执行一律 argv 直发,不经 shell。
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

	"github.com/Daedalusys/daedalus-sdk/audit"
	"github.com/Daedalusys/daedalus-sdk/sysinfo"
	"github.com/Daedalusys/daedalus-sdk/version"
)

const serverName = "daedalus-snapshot"

// execCommand 是唯一执行外部命令的入口(形状照 service 的二进制注入点);
// 测试替换它,单测永不执行宿主上的 btrfs/lvs/snapper。
var execCommand = sysinfo.ExecCommand

// pathExists 只做存在性探测:不打开、不执行。放包级变量是为了让测试用内存集合
// 替换它,而不是去 mock 整棵宿主文件树。
var pathExists = func(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// recordAudit 追加一条哈希链审计条目(只读工具,尽力而为,失败仅留一行
// stderr 警告)。采集故障折叠进回包的 error 键而非错误结果,故成功按
// "success" 记录;仅当结果本身 isError(如序列化失败)按 "error"。
func recordAudit(tool string, res *mcp.CallToolResult) {
	outcome := "success"
	args := map[string]any{}
	if res != nil && res.IsError {
		outcome = "error"
		if len(res.Content) > 0 {
			if text, ok := res.Content[0].(*mcp.TextContent); ok {
				args["error"] = shortText(text.Text)
			}
		}
	}
	var v *audit.Value
	data, err := json.Marshal(args)
	if err == nil {
		v, err = audit.ParseValue(string(data))
	}
	if err == nil {
		_, err = audit.LogAudit(audit.Entry{
			Identity: serverName,
			Tool:     tool,
			Args:     v,
			Outcome:  outcome,
		})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: 审计写入失败: %v\n", serverName, err)
	}
}

// shortText 截取错误文本,防超大载荷灌进哈希链。
func shortText(s string) string {
	const maxRunes = 200
	r := []rune(s)
	if len(r) > maxRunes {
		return string(r[:maxRunes]) + "…"
	}
	return string(r)
}

func main() {
	server := newServer()

	// SIGINT/SIGTERM 触发优雅退出;Run 返回后错误信息写 stderr,
	// 以保持 stdout 的 JSON-RPC 数据流完整。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !isCleanShutdown(err) {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}
}

// isCleanShutdown 判定"正常结束":stdin 客户端断开(context.Canceled / EOF)与
// SDK 内部 jsonrpc2.ErrServerClosing("server is closing: ...")。
// ErrServerClosing 位于 internal 包无法用 errors.Is 匹配,按消息前缀归类。
func isCleanShutdown(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return true
	}
	return strings.HasPrefix(err.Error(), "server is closing")
}

func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	// go-sdk 的 DestructiveHint/OpenWorldHint 为 *bool 且 SDK 未导出取址助手,
	// 按实证形态用局部变量取址(只读工具必然非破坏性、封闭世界)。
	nonDestructive := false
	closedWorld := false
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  true,
		OpenWorldHint:   &closedWorld,
	}

	mcp.AddTool(server, &mcp.Tool{
		Name: "snapshot_backends",
		Description: "返回本机快照后端工具的探测结果（只读）。\n\n" +
			"按固定绝对路径候选表 stat 探测 btrfs/rsync,命中后再执行 `--version` 自报版本。\n" +
			"available 回答的是「后端工具是否就位且能自报版本」,不是「当前挂载点能否被\n" +
			"快照」—— 后者请结合 filesystem_info 的 fstype 判断。\n\n" +
			"参数：\n" +
			"    mountpoints: 回显用的挂载点列表；省略时为 [\"/\"]，不影响探测结论。\n\n" +
			"返回：\n" +
			"    {mountpoints, backends:[{name,available,evidence}], recommended, supports_rollback}。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"mountpoints": {
					Type:        "array",
					Items:       &jsonschema.Schema{Type: "string"},
					Description: "回显用的挂载点列表；省略时为 [\"/\"]，不参与 available 判定。",
				},
			},
		},
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in backendsIn) (*mcp.CallToolResult, any, error) {
		res := jsonResult(snapshotBackendsPayload(ctx, in))
		recordAudit("snapshot_backends", res)
		return res, nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "snapshot_list",
		Description: "列举现有快照（只读）。\n\n" +
			"按后端执行只读列举：btrfs `subvolume list -o /`、lvm `lvs` 查询、\n" +
			"snapper `--csvout list`；rsync 没有快照注册表，恒为空数组。\n" +
			"本工具绝不创建、删除或回滚快照。\n\n" +
			"参数：\n" +
			"    backend: btrfs|lvm|snapper|rsync；省略时用 snapshot_backends 的 recommended。\n\n" +
			"返回：\n" +
			"    {\"backend\":...,\"snapshots\":[{id,name},...]}；后端未知或不可用时是空数组\n" +
			"    （不是错误），命令真执行失败时附带 error 键。",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"backend": {
					Type:        "string",
					Description: "btrfs|lvm|snapper|rsync；省略时用 snapshot_backends 的 recommended。",
				},
			},
		},
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in snapshotListIn) (*mcp.CallToolResult, any, error) {
		res := jsonResult(snapshotListPayload(ctx, in))
		recordAudit("snapshot_list", res)
		return res, nil, nil
	})

	return server
}

// jsonResult 对应 Python FastMCP 的 json.dumps(..., ensure_ascii=False,
// indent=2);Go 端用 SetEscapeHTML(false) + SetIndent("  ") 等价实现。
func jsonResult(v any) *mcp.CallToolResult {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return toolError(err)
	}
	// Encoder.Encode 追加换行,py json.dumps 不带,尾部去除。
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.TrimSuffix(buf.String(), "\n")}},
	}
}

func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
		IsError: true,
	}
}
