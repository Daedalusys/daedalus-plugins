// Command daedalus-fs 是文件系统能力 MCP 服务器(stdio JSON-RPC)。
//
// 行为规格源:daedalus/files/system/opt/daedalus/deno/fs_server.ts(生产实现)。
// 提供 4 个工具(read_file / write_file / list_dir / move_file),所有路径
// 经由 internal/pathguard 白名单校验(默认 /home、/var/log、/tmp)。Go 无运行时
// 权限标志,安全边界全部 in-code 强制。
//
// 策略来源(计划 todo 12):白名单启动时从 shared/policy.toml
// (internal/policy)读取并注入 pathguard;文件缺失回退 Default(),
// 损坏则拒绝启动(fail-closed)。
//
// 清单交叉引用:本插件 manifest(daedalus.plugin.json)的 resources 声明字段
// (本插件 v1 未声明)schema 单一事实源见
// daedalus/core/internal/objectmodel/objectmodel.go
// (计划 .omo/plans/aios-object-model-alignment.md 决策 25;
// JSON 清单不能携带注释,故引用住本文件头)。
//
// 工具描述、参数名(path/content/src/dst)、required 列表与 ToolAnnotations
// 与 fs_server.ts:210-299 逐字一致;错误结果对应 handleJsonRpcMessage 的
// catch 分支(440-454 行):isError=true 且文本以 "Error: " 开头。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"unicode/utf16"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/pathguard"
	"github.com/Daedalusys/daedalus-sdk/policy"
	"github.com/Daedalusys/daedalus-sdk/version"
)

// serverName 与 fs_server.ts:359 的 serverInfo.name 一致。
const serverName = "daedalus-fs"

// —— 工具输入类型(字段名/required 与 fs_server.ts MCP_TOOLS 的 inputSchema 一致;
//
//	jsonschema 标签即参数描述,对应 ts 各 property 的 description)——
type (
	readFileIn struct {
		Path string `json:"path" jsonschema:"Absolute path to the file to read."`
	}
	writeFileIn struct {
		Path    string `json:"path" jsonschema:"Absolute path to the destination file."`
		Content string `json:"content" jsonschema:"Text content to write into the file."`
	}
	listDirIn struct {
		Path string `json:"path" jsonschema:"Absolute path to the directory."`
	}
	moveFileIn struct {
		Src string `json:"src" jsonschema:"Absolute path to the source file or directory."`
		Dst string `json:"dst" jsonschema:"Absolute path to the destination file or directory."`
	}
)

func main() {
	// 单一事实源(计划 todo 12):启动时读 shared/policy.toml 并注入
	// pathguard。文件整体缺失时 LoadOrDefault 回退 Default()(服务器
	// 仍可启动);文件存在但损坏/字段缺失属 fail-closed → 拒绝启动。
	if err := applyPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}

	server := newServer()

	// SIGINT/SIGTERM 触发优雅退出;Run 返回后错误信息写 stderr,
	// 以保持 stdout 的 JSON-RPC 数据流完整(对应 fs_server.ts:531-534)。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !isCleanShutdown(err) {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}
}

// applyPolicy 加载策略(缺失回退 Default)并把 [fs].allowed_dirs 注入
// pathguard 包级白名单。与测试共用同一入口:测试经 DAEDALUS_POLICY_PATH
// 环境变量指向 testdata 后调用本函数即可演练白名单跟随。
func applyPolicy() error {
	p, err := policy.LoadOrDefault()
	if err != nil {
		return fmt.Errorf("policy load failed, refusing to start: %w", err)
	}
	pathguard.WithAllowedDirs(p.FS.AllowedDirs)
	return nil
}

// isCleanShutdown 判定"正常结束":stdin 客户端断开(context.Canceled / EOF)与
// SDK 内部 jsonrpc2.ErrServerClosing("server is closing: ...")。ts 版
// runServer 在 stdin EOF 时正常退出循环(退出码 0),Go 侧据此对齐;
// ErrServerClosing 位于 internal 包无法用 errors.Is 匹配,按消息前缀归类。
func isCleanShutdown(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return true
	}
	return strings.HasPrefix(err.Error(), "server is closing")
}

// newServer 构造并注册全部 4 个工具(测试与 main 共用同一构造入口)。
func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	// go-sdk v1.7.0 的 DestructiveHint/OpenWorldHint 为 *bool 且 SDK 未导出
	// 取址助手,按实证形态用局部变量取址。
	nonDestructive := false
	destructive := true
	closedWorld := false

	mcp.AddTool(server, &mcp.Tool{
		Name:        "read_file",
		Description: "Read text content from a file within allowed directories (/home, /var/log, /tmp).",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: &nonDestructive,
			IdempotentHint:  true,
			OpenWorldHint:   &closedWorld,
		},
	}, handleReadFile)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "write_file",
		Description: "Write or overwrite text content to a file within allowed directories (/home, /var/log, /tmp). Automatically creates parent directories if they do not exist.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: &destructive,
			IdempotentHint:  true,
			OpenWorldHint:   &closedWorld,
		},
	}, handleWriteFile)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_dir",
		Description: "List contents of a directory within allowed directories (/home, /var/log, /tmp).",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: &nonDestructive,
			IdempotentHint:  true,
			OpenWorldHint:   &closedWorld,
		},
	}, handleListDir)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "move_file",
		Description: "Move or rename a file or directory within allowed directories (/home, /var/log, /tmp). Both source and destination must be strictly inside the allowed whitelist.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: &destructive,
			IdempotentHint:  false, // ts: idempotentHint=false
			OpenWorldHint:   &closedWorld,
		},
	}, handleMoveFile)

	return server
}

// handleReadFile 移植 fs_server.ts:115-127(readFileTool)。
func handleReadFile(_ context.Context, _ *mcp.CallToolRequest, in readFileIn) (*mcp.CallToolResult, any, error) {
	safePath, err := pathguard.ValidatePath(in.Path, false)
	if err != nil {
		return toolError(err), nil, nil
	}
	info, err := os.Stat(safePath)
	if err != nil {
		return toolError(err), nil, nil
	}
	if info.IsDir() {
		return toolError(fmt.Errorf("Target is a directory, not a file: %s", in.Path)), nil, nil
	}
	data, err := os.ReadFile(safePath)
	if err != nil {
		return toolError(err), nil, nil
	}
	return textResult(string(data)), nil, nil
}

// handleWriteFile 移植 fs_server.ts:132-159(write_fileTool)。
func handleWriteFile(_ context.Context, _ *mcp.CallToolRequest, in writeFileIn) (*mcp.CallToolResult, any, error) {
	safePath, err := pathguard.ValidatePath(in.Path, true)
	if err != nil {
		return toolError(err), nil, nil
	}
	if info, err := os.Stat(safePath); err == nil && info.IsDir() {
		return toolError(fmt.Errorf("Target is a directory: %s", in.Path)), nil, nil
	}
	// 自动创建父目录;已存在或创建失败均如 ts 一样静默(对应 151-154 行空 catch)。
	mkdirParent(safePath)
	if err := os.WriteFile(safePath, []byte(in.Content), 0o644); err != nil {
		return toolError(err), nil, nil
	}
	// ts 的 content.length 是 UTF-16 码元数,Go 端显式复刻以保证消息逐字等价。
	return textResult(fmt.Sprintf("Successfully wrote %d characters to %s", utf16Length(in.Content), in.Path)), nil, nil
}

// handleListDir 移植 fs_server.ts:164-181(listDirTool):
// 目录项名排序后以 JSON 数组(indent=2)作为文本返回(ts 的 JSON.stringify)。
func handleListDir(_ context.Context, _ *mcp.CallToolRequest, in listDirIn) (*mcp.CallToolResult, any, error) {
	safePath, err := pathguard.ValidatePath(in.Path, false)
	if err != nil {
		return toolError(err), nil, nil
	}
	info, err := os.Stat(safePath)
	if err != nil {
		return toolError(err), nil, nil
	}
	if !info.IsDir() {
		return toolError(fmt.Errorf("Target is not a directory: %s", in.Path)), nil, nil
	}
	dirEntries, err := os.ReadDir(safePath)
	if err != nil {
		return toolError(err), nil, nil
	}
	names := make([]string, 0, len(dirEntries))
	for _, e := range dirEntries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	encoded, err := json.MarshalIndent(names, "", "  ")
	if err != nil {
		return toolError(err), nil, nil
	}
	return textResult(string(encoded)), nil, nil
}

// handleMoveFile 移植 fs_server.ts:186-205(moveFileTool)。
func handleMoveFile(_ context.Context, _ *mcp.CallToolRequest, in moveFileIn) (*mcp.CallToolResult, any, error) {
	safeSrc, err := pathguard.ValidatePath(in.Src, true)
	if err != nil {
		return toolError(err), nil, nil
	}
	safeDst, err := pathguard.ValidatePath(in.Dst, true)
	if err != nil {
		return toolError(err), nil, nil
	}
	mkdirParent(safeDst)
	if err := os.Rename(safeSrc, safeDst); err != nil {
		return toolError(err), nil, nil
	}
	return textResult(fmt.Sprintf("Successfully moved %s to %s", in.Src, in.Dst)), nil, nil
}

// mkdirParent 对应 ts 的 "取最后一个 '/' 之前的父目录并 mkdir -p、失败静默":
// safePath 已经过 ValidatePath 规范化,必然以 '/' 开头且不是裸 "/"。
func mkdirParent(safePath string) {
	parentDir := safePath[:strings.LastIndex(safePath, "/")]
	if parentDir != "" {
		_ = os.MkdirAll(parentDir, 0o755)
	}
}

// utf16Length 计算字符串的 UTF-16 码元数,等价于 JS 的 string.length。
func utf16Length(s string) int {
	return len(utf16.Encode([]rune(s)))
}

// textResult 构造成功结果(对应 ts 431-439 行的单 text content 块)。
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// toolError 对应 ts handleJsonRpcMessage 的 catch 分支(440-454 行):
// isError=true,文本为 "Error: " + 错误消息。
func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "Error: " + err.Error()}},
		IsError: true,
	}
}
