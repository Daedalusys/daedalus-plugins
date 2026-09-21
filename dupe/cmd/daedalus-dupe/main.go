// Command daedalus-dupe 是大文件与重复文件扫描能力 MCP 服务器(stdio JSON-RPC)。
//
// 行为规格源:daedalus-plugins issue #4(Daedalus Large & Duplicate File
// Scanner)。对外提供 2 个只读工具:
//
//   - scan_large:递归遍历单个目录,按体积降序返回最大的 top_n 个普通文件;
//   - scan_dupes:在给定目录集合内按 size_only / first_1mb / sha256 三种算法
//     找出重复文件分组,并给出每组可回收空间(wasted_bytes)与是否同目录。
//
// 本插件与 fs 插件同属 L0 只读能力:所有路径先经 daedalus-sdk/pathguard
// 白名单校验(默认 /home、/var/log、/tmp),不写文件、不调外部进程、
// 不发网络请求。白名单在启动时从 shared/policy.toml(policy.LoadOrDefault)
// 读取并注入:文件缺失回退 Default(),损坏则拒绝启动(fail-closed)。
//
// 长扫描通过 MCP 协议级 notifications/progress 上报进度
// (ServerSession.NotifyProgress),不向 stdout/stderr 打印任何日志,
// 以免污染 JSON-RPC 数据流。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/pathguard"
	"github.com/Daedalusys/daedalus-sdk/policy"
	"github.com/Daedalusys/daedalus-sdk/version"
)

// serverName 与 manifest(daedalus.plugin.json)的插件 id 语义一致。
const serverName = "daedalus-dupe"

// scan_dupes 支持的三种重复判定算法标识;表外取值一律报错。
const (
	algoSizeOnly = "size_only"
	algoFirst1MB = "first_1mb"
	algoSHA256   = "sha256"
)

// firstChunkSize 是 first_1mb 算法参与哈希的文件头长度(1 MiB)。
const firstChunkSize = 1 << 20

// defaultTopN 是 scan_large 未显式给出 top_n 时的默认返回条数。
const defaultTopN = 20

// progressStep 是每处理多少个文件上报一次 MCP 进度。
const progressStep = 100

// MCP go-sdk v1.8.0 的 ToolAnnotations.DestructiveHint / OpenWorldHint 字段
// 类型为 *bool,且 SDK 未导出取址助手,故按实证形态声明包级哨兵变量后取址
// (直接写 plain false 字面量无法通过编译)。
var nonDestructive = false
var closedWorld = false

// —— 工具输入类型(字段名即 MCP inputSchema 属性名;jsonschema 标签即描述)——

type (
	// ScanLargeInput 是 scan_large 的入参。
	ScanLargeInput struct {
		Dir     string `json:"dir" jsonschema:"Absolute path to the directory to scan."`
		MinSize int64  `json:"min_size,omitempty" jsonschema:"Minimum file size in bytes to report. Defaults to 0 (every regular file)."`
		TopN    int    `json:"top_n,omitempty" jsonschema:"Maximum number of entries to return, sorted by size descending. Defaults to 20."`
	}
	// ScanDupesInput 是 scan_dupes 的入参。
	ScanDupesInput struct {
		Dirs    []string `json:"dirs" jsonschema:"Absolute paths to the directories scanned for duplicate files."`
		MinSize int64    `json:"min_size,omitempty" jsonschema:"Minimum file size in bytes to consider. Defaults to 0."`
		Algo    string   `json:"algo" jsonschema:"Duplicate detection algorithm: size_only, first_1mb, or sha256."`
	}
)

// —— 工具输出类型(JSON 渲染到 text content 块)——

// largeEntry 是 scan_large 返回的单条大文件记录。
type largeEntry struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	MTime string `json:"mtime"`
	Type  string `json:"type"`
}

// dupeGroup 是 scan_dupes 返回的一个重复文件分组。
type dupeGroup struct {
	GroupID     string   `json:"group_id"`
	Files       []string `json:"files"`
	WastedBytes int64    `json:"wasted_bytes"`
	SameDir     bool     `json:"same_dir"`
}

// scannedFile 是遍历过程中采集到的普通文件元信息。
type scannedFile struct {
	path  string
	size  int64
	mtime time.Time
}

func main() {
	// 单一事实源:启动时读 shared/policy.toml 并注入 pathguard。
	// 文件整体缺失时 LoadOrDefault 回退 Default()(服务器仍可启动);
	// 文件存在但损坏/字段缺失属 fail-closed → 拒绝启动。
	if err := applyPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}

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
// SDK 内部 jsonrpc2.ErrServerClosing("server is closing: ...")。
// ErrServerClosing 位于 internal 包无法用 errors.Is 匹配,按消息前缀归类。
func isCleanShutdown(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return true
	}
	return strings.HasPrefix(err.Error(), "server is closing")
}

// newServer 构造并注册全部 2 个只读工具(测试与 main 共用同一构造入口)。
func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_large",
		Description: "Scan a directory tree for the largest regular files within allowed directories (/home, /var/log, /tmp). Returns up to top_n entries sorted by size descending.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: &nonDestructive,
			IdempotentHint:  true,
			OpenWorldHint:   &closedWorld,
		},
	}, scanLarge)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_dupes",
		Description: "Find duplicate files across the given directories within allowed directories (/home, /var/log, /tmp) using size_only, first_1mb, or sha256. Returns duplicate groups with reclaimable bytes.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: &nonDestructive,
			IdempotentHint:  true,
			OpenWorldHint:   &closedWorld,
		},
	}, scanDupes)

	return server
}

// scanLarge 遍历 in.Dir,按体积降序返回最大的 top_n 个普通文件。
//
// 目录符号链接一律不跟随(防白名单逃逸与目录环);单层目录读取失败跳过
// 而不中断整体扫描。取消信号经 ctx 贯穿遍历与排序后的每个阶段。
func scanLarge(ctx context.Context, req *mcp.CallToolRequest, in ScanLargeInput) (*mcp.CallToolResult, any, error) {
	safeDir, err := pathguard.ValidatePath(in.Dir, false)
	if err != nil {
		return toolError(err), nil, nil
	}
	info, err := os.Stat(safeDir)
	if err != nil {
		return toolError(err), nil, nil
	}
	if !info.IsDir() {
		return toolError(fmt.Errorf("Target is not a directory: %s", in.Dir)), nil, nil
	}

	topN := in.TopN
	if topN <= 0 {
		topN = defaultTopN
	}

	entries := make([]largeEntry, 0)
	err = walkFiles(ctx, safeDir, in.MinSize, func(f *scannedFile) {
		entries = append(entries, largeEntry{
			Path:  f.path,
			Size:  f.size,
			MTime: f.mtime.UTC().Format(time.RFC3339),
			Type:  "file",
		})
	}, func(scanned int) { reportProgress(ctx, req, scanned) })
	if err != nil {
		return nil, nil, err
	}

	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Size > entries[j].Size })
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	if len(entries) > topN {
		entries = entries[:topN]
	}
	encoded, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return toolError(err), nil, nil
	}
	return textResult(string(encoded)), nil, nil
}

// scanDupes 在 in.Dirs 目录集合内按 in.Algo 找出重复文件分组。
//
// 算法语义:
//   - size_only:仅按文件体积分桶,桶内 >= 2 个文件即成组(最快、可能误报);
//   - first_1mb:按文件头 1 MiB 的 SHA-256 分组(适合大文件快速预筛);
//   - sha256:按整文件 SHA-256 分组(最准、需要完整读取)。
//
// 每个目录先过 pathguard;同名的同一路径跨目录去重,防止重复计数。
func scanDupes(ctx context.Context, req *mcp.CallToolRequest, in ScanDupesInput) (*mcp.CallToolResult, any, error) {
	switch in.Algo {
	case algoSizeOnly, algoFirst1MB, algoSHA256:
		// 三种受支持算法,继续。
	default:
		return toolError(fmt.Errorf("unknown algo %q (supported: size_only|first_1mb|sha256)", in.Algo)), nil, nil
	}
	if len(in.Dirs) == 0 {
		return toolError(errors.New("dirs must contain at least one directory")), nil, nil
	}

	roots := make([]string, 0, len(in.Dirs))
	for _, dir := range in.Dirs {
		safeDir, err := pathguard.ValidatePath(dir, false)
		if err != nil {
			return toolError(err), nil, nil
		}
		info, err := os.Stat(safeDir)
		if err != nil {
			return toolError(err), nil, nil
		}
		if !info.IsDir() {
			return toolError(fmt.Errorf("Target is not a directory: %s", dir)), nil, nil
		}
		roots = append(roots, safeDir)
	}

	// 采集阶段:跨根目录按路径去重(嵌套根目录会重复看到同一文件)。
	seen := make(map[string]struct{})
	files := make([]scannedFile, 0)
	for _, root := range roots {
		err := walkFiles(ctx, root, in.MinSize, func(f *scannedFile) {
			if _, ok := seen[f.path]; ok {
				return
			}
			seen[f.path] = struct{}{}
			files = append(files, *f)
		}, func(scanned int) { reportProgress(ctx, req, scanned) })
		if err != nil {
			return nil, nil, err
		}
	}

	// 分组阶段进度从"已采集文件总数"起算,保持单调递增。
	groups, err := groupDuplicates(ctx, files, in.Algo, func(done int) {
		reportProgress(ctx, req, len(files)+done)
	})
	if err != nil {
		return nil, nil, err
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	encoded, err := json.MarshalIndent(groups, "", "  ")
	if err != nil {
		return toolError(err), nil, nil
	}
	return textResult(string(encoded)), nil, nil
}

// walkFiles 以显式栈深度优先遍历 root(显式 os.Lstat,不用 filepath.WalkDir
// 的隐式行为),把 size >= minSize 的普通文件交给 emit:
//   - 符号链接(含指向目录的链接)一律跳过,既防白名单逃逸也防目录环;
//   - 目录不可读、条目 Lstat 失败等局部错误跳过,不中断整体扫描;
//   - 每轮迭代检查 ctx 取消,长扫描可被随时打断;
//   - 每处理 progressStep 个文件回调一次 progress(可为 nil)。
func walkFiles(ctx context.Context, root string, minSize int64, emit func(*scannedFile), progress func(int)) error {
	stack := []string{root}
	scanned := 0
	for len(stack) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		dirEntries, err := os.ReadDir(dir)
		if err != nil {
			continue // 权限不足/竞态删除:跳过该目录。
		}
		for _, entry := range dirEntries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			path := filepath.Join(dir, entry.Name())
			info, err := os.Lstat(path)
			if err != nil {
				continue // 扫描期间消失的条目:跳过。
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue // 符号链接绝不跟随。
			}
			if info.IsDir() {
				stack = append(stack, path)
				continue
			}
			if !info.Mode().IsRegular() || info.Size() < minSize {
				continue // 设备/管道/套接字与不达标的文件不参与统计。
			}
			scanned++
			if progress != nil && scanned%progressStep == 0 {
				progress(scanned)
			}
			emit(&scannedFile{path: path, size: info.Size(), mtime: info.ModTime()})
		}
	}
	return nil
}

// groupDuplicates 按 algo 对采集到的文件分组,仅保留 >= 2 个成员的分组。
// 读取失败(权限/文件消失)的单个文件跳过而不中断整体扫描;
// 分组按 wasted_bytes 降序、group_id 升序输出,保证结果稳定可比。
func groupDuplicates(ctx context.Context, files []scannedFile, algo string, progress func(int)) ([]dupeGroup, error) {
	buckets := make(map[string][]scannedFile)
	for i, f := range files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		key, err := groupKey(ctx, f, algo)
		if err != nil {
			continue
		}
		buckets[key] = append(buckets[key], f)
		if progress != nil && (i+1)%progressStep == 0 {
			progress(i + 1)
		}
	}

	groups := make([]dupeGroup, 0)
	for key, bucket := range buckets {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if len(bucket) < 2 {
			continue
		}
		paths := make([]string, 0, len(bucket))
		for _, f := range bucket {
			paths = append(paths, f.path)
		}
		sort.Strings(paths)
		groups = append(groups, dupeGroup{
			GroupID:     key,
			Files:       paths,
			WastedBytes: wastedBytes(bucket),
			SameDir:     sameDir(paths),
		})
	}

	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].WastedBytes != groups[j].WastedBytes {
			return groups[i].WastedBytes > groups[j].WastedBytes
		}
		return groups[i].GroupID < groups[j].GroupID
	})
	return groups, nil
}

// groupKey 计算单个文件的分组键:
//   - size_only → "size-<字节数>";
//   - first_1mb → "first1mb-<头 1 MiB 的 sha256 前 16 位>";
//   - sha256 → "sha256-<整文件 sha256 前 16 位>"。
func groupKey(ctx context.Context, f scannedFile, algo string) (string, error) {
	switch algo {
	case algoSizeOnly:
		return fmt.Sprintf("size-%d", f.size), nil
	case algoFirst1MB, algoSHA256:
		sum, err := digestFile(ctx, f.path, algo)
		if err != nil {
			return "", err
		}
		if algo == algoFirst1MB {
			return "first1mb-" + sum[:16], nil
		}
		return "sha256-" + sum[:16], nil
	default:
		return "", fmt.Errorf("unknown algo %q (supported: size_only|first_1mb|sha256)", algo)
	}
}

// digestFile 以流式方式计算文件摘要:first_1mb 只读前 1 MiB,
// sha256 读完整文件。每次读循环都检查 ctx 取消,避免大文件卡住退出。
func digestFile(ctx context.Context, path, algo string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	buf := make([]byte, firstChunkSize)
	var limit int64 = -1
	if algo == algoFirst1MB {
		limit = firstChunkSize
	}

	var read int64
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		if limit >= 0 && read >= limit {
			break
		}
		n, err := file.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if limit >= 0 && read+int64(n) > limit {
				chunk = chunk[:limit-read]
			}
			hasher.Write(chunk)
			read += int64(len(chunk))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// wastedBytes 计算组内可回收空间:总和减去保留一份所需的体积
// (成员体积不齐时按最大者保留,如 first_1mb 的前缀碰撞组)。
func wastedBytes(bucket []scannedFile) int64 {
	var total, largest int64
	for _, f := range bucket {
		total += f.size
		if f.size > largest {
			largest = f.size
		}
	}
	return total - largest
}

// sameDir 判定组内文件是否全部位于同一目录(排序后的路径列表)。
func sameDir(paths []string) bool {
	if len(paths) == 0 {
		return false
	}
	dir := filepath.Dir(paths[0])
	for _, p := range paths[1:] {
		if filepath.Dir(p) != dir {
			return false
		}
	}
	return true
}

// reportProgress 经 MCP 协议级 notifications/progress 上报已扫描文件数。
// req / req.Session 为 nil(直接单测调用)时静默跳过;
// ProgressNotificationParams.Progress 是 float64,需显式转换。
func reportProgress(ctx context.Context, req *mcp.CallToolRequest, scanned int) {
	if req == nil || req.Session == nil {
		return
	}
	_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
		ProgressToken: "dupe",
		Progress:      float64(scanned),
	})
}

// textResult 构造成功结果(单个 text content 块)。
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// toolError 构造错误结果:isError=true,文本为 "Error: " + 错误消息,
// 与 fs 插件的错误形态保持一致。
func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "Error: " + err.Error()}},
		IsError: true,
	}
}
