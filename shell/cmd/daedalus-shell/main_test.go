// daedalus-shell 的行为测试:真实 MCP 握手断言工具规格,并端到端验证
// 白名单拒绝(126)、真实执行、净化环境、进程组超时(124)与审计落盘。
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/audit"
	"github.com/Daedalusys/daedalus-sdk/policy"
	"github.com/Daedalusys/daedalus-sdk/shellpolicy"
)

// testConfig 构造指向隔离审计文件的服务器配置(默认白名单 + 30s 超时)。
func testConfig(t *testing.T, allowEnv string) serverConfig {
	t.Helper()
	return serverConfig{
		allow:     shellpolicy.ResolveAllowCommands(allowEnv),
		auditPath: mustCreateAuditFile(t),
		timeout:   shellpolicy.Timeout,
	}
}

// mustCreateAuditFile 预创建空审计文件:recordAudit 以 create:false 打开,
// 文件必须已存在才会真正落盘(与 ts 语义一致)。
func mustCreateAuditFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("创建审计文件失败: %v", err)
	}
	_ = f.Close()
	return path
}

func connectSession(t *testing.T, cfg serverConfig) (*mcp.ClientSession, context.Context) {
	t.Helper()
	server := newServer(cfg)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "shell-test-client", Version: "0.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("MCP 握手失败: %v", err)
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Errorf("关闭会话失败: %v", err)
		}
		if err := <-serverDone; err != nil {
			t.Errorf("服务器退出异常: %v", err)
		}
	})
	return session, ctx
}

// callShell 经真实 JSON-RPC 往返调用 shell_exec,解析文本 JSON 回包。
func callShell(t *testing.T, session *mcp.ClientSession, ctx context.Context, command string, args []string) (execResult, bool) {
	t.Helper()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "shell_exec",
		Arguments: toolArgs(command, args),
	})
	if err != nil {
		t.Fatalf("tools/call shell_exec 传输失败: %v", err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("回包内容块数量 = %d, want 1", len(res.Content))
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("回包非文本: %T", res.Content[0])
	}
	var parsed execResult
	if err := json.Unmarshal([]byte(text.Text), &parsed); err != nil {
		t.Fatalf("回包 JSON 解析失败: %v\n原文: %s", err, text.Text)
	}
	return parsed, res.IsError
}

// TestShellToolsList_MatchesDenoSpec 断言唯一工具的名称/描述/注解/schema。
func TestShellToolsList_MatchesDenoSpec(t *testing.T) {
	session, ctx := connectSession(t, testConfig(t, ""))
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list 失败: %v", err)
	}
	if len(res.Tools) != 1 {
		t.Fatalf("工具数量 = %d, want 1", len(res.Tools))
	}
	tool := res.Tools[0]

	if tool.Name != "shell_exec" {
		t.Errorf("工具名 = %q", tool.Name)
	}
	// 与 shell_server.ts:359-360 逐字一致。
	wantDesc := "Execute an allowlisted command with arguments safely (read-only / diagnostic). Restricted to an argv allowlist with strict argument path validation and 30s timeout."
	if tool.Description != wantDesc {
		t.Errorf("描述漂移:\n got %q\nwant %q", tool.Description, wantDesc)
	}

	a := tool.Annotations
	if a == nil {
		t.Fatal("缺 Annotations")
	}
	if a.ReadOnlyHint != true || a.IdempotentHint != true {
		t.Errorf("readOnly/idempotent = %v/%v, want true/true", a.ReadOnlyHint, a.IdempotentHint)
	}
	if a.DestructiveHint == nil || *a.DestructiveHint != false {
		t.Errorf("destructiveHint = %v, want false", a.DestructiveHint)
	}
	if a.OpenWorldHint == nil || *a.OpenWorldHint != false {
		t.Errorf("openWorldHint = %v, want false", a.OpenWorldHint)
	}

	schema, ok := tool.InputSchema.(map[string]any)
	if !ok {
		t.Fatalf("inputSchema 类型异常: %T", tool.InputSchema)
	}
	req, _ := schema["required"].([]any)
	if len(req) != 1 || req[0] != "command" {
		t.Errorf(`required = %v, want ["command"]`, req)
	}
	props, _ := schema["properties"].(map[string]any)
	if _, ok := props["command"]; !ok {
		t.Error("properties 缺 command")
	}
	argsSchema, ok := props["args"].(map[string]any)
	if !ok {
		t.Fatalf("properties 缺 args: %v", props)
	}
	// Go nil slice 被 SDK 推断为 ["null","array"] 联合类型。这是 Go 类型
	// 反射产物而非语义漂移:ts 版对 args:null 的处理(shell_server.ts:456-458,
	// Array.isArray 失败 → [])恰好要求 schema 接受显式 null,联合类型比
	// 字面 "array" 更贴近 ts 行为。断言集合必须含 "array" 且无其它意外成员。
	gotTypes := schemaTypes(argsSchema["type"])
	if !slices.Contains(gotTypes, "array") || len(gotTypes) > 2 || (len(gotTypes) == 2 && !slices.Contains(gotTypes, "null")) {
		t.Errorf("args type = %v, want array(可含 null)", gotTypes)
	}
	if items, ok := argsSchema["items"].(map[string]any); !ok || items["type"] != "string" {
		t.Errorf("args items 异常: %v", argsSchema["items"])
	}
}

// schemaTypes 归一化 JSON Schema type 字段(字符串或字符串数组)。
func schemaTypes(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, s := range t {
			if str, ok := s.(string); ok {
				out = append(out, str)
			}
		}
		slices.Sort(out)
		return out
	default:
		return nil
	}
}

// toolArgs 组装 tools/call 参数:nil 时整体省略 args 键
// (对应 ts 中缺省 args 归一为 [] 的 handler 行为)。
func toolArgs(command string, args []string) map[string]any {
	m := map[string]any{"command": command}
	if args != nil {
		m["args"] = args
	}
	return m
}

// TestShellExec_Rejections 覆盖计划要求的拒绝路径:rm/bash 命令、
// 非系统 bin 目录、受阻路径参数、覆盖式白名单。
func TestShellExec_Rejections(t *testing.T) {
	tests := []struct {
		name    string
		allow   string
		command string
		args    []string
		wantIn  string // stderr 必含子串
	}{
		{"rm 不在白名单", "", "rm", []string{"-rf", "/"}, "Command 'rm' is not in ALLOW_COMMANDS allowlist"},
		{"bash 不在白名单", "", "bash", []string{"-c", "echo hi"}, "not in ALLOW_COMMANDS allowlist"},
		{"usr-local-bin 拒绝", "", "/usr/local/bin/df", nil, "not in a valid system bin directory"},
		{"受阻路径参数", "", "cat", []string{"/etc/shadow"}, "Access to blocked path"},
		{"flag等号受阻路径", "", "ls", []string{"--file=/etc/shadow"}, "Access to blocked path"},
		{"ALLOW_COMMANDS 替换后 cat 被拒", "df,ls", "cat", []string{"/etc/os-release"}, "Command 'cat' is not in ALLOW_COMMANDS allowlist"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			session, ctx := connectSession(t, testConfig(t, tc.allow))
			res, isErr := callShell(t, session, ctx, tc.command, tc.args)
			if !isErr {
				t.Fatalf("拒绝路径 isError=false: %+v", res)
			}
			if res.Returncode != shellpolicy.ValidationRejectionCode {
				t.Errorf("returncode = %d, want 126", res.Returncode)
			}
			if res.Stdout != "" {
				t.Errorf("stdout = %q, want 空", res.Stdout)
			}
			if !strings.HasPrefix(res.Stderr, "Command validation failed:") && !strings.HasPrefix(res.Stderr, "Argument validation failed:") {
				t.Errorf("stderr 前缀漂移: %q", res.Stderr)
			}
			if res.Error == nil || !strings.Contains(*res.Error, tc.wantIn) {
				t.Errorf("error = %v, 应含 %q", res.Error, tc.wantIn)
			}
		})
	}
}

// TestShellExec_RealCommands 用真实命令证明成功路径与退出码透传。
func TestShellExec_RealCommands(t *testing.T) {
	session, ctx := connectSession(t, testConfig(t, ""))

	res, isErr := callShell(t, session, ctx, "uname", []string{"-s"})
	if isErr || res.Returncode != 0 {
		t.Fatalf("uname -s 失败: %+v", res)
	}
	if strings.TrimSpace(res.Stdout) != "Linux" {
		t.Errorf("uname stdout = %q, want Linux", res.Stdout)
	}
	if res.Error != nil {
		t.Errorf("成功路径不应带 error 字段: %v", res.Error)
	}

	// ls 不存在的路径 → GNU ls 真实退出码 2,原样透传(不是 126/1)。
	res, isErr = callShell(t, session, ctx, "ls", []string{"/tmp/definitely-missing-daedalus-test"})
	if !isErr || res.Returncode != 2 {
		t.Fatalf("非零退出码透传失败: %+v", res)
	}
	if !strings.Contains(res.Stderr, "cannot access") && !strings.Contains(res.Stderr, "No such file") {
		t.Errorf("ls stderr 异常: %q", res.Stderr)
	}

	// 空 args(nil)等价缺省,命令可正常执行。
	res, _ = callShell(t, session, ctx, "whoami", nil)
	if res.Returncode != 0 {
		t.Errorf("whoami 失败: %+v", res)
	}
}

// TestShellExec_CleanEnvOnly 直接验证 execute 层:子进程环境恰为 CLEAN_ENV
// 两项,零继承(HOME/USER/PATH 覆盖等一律不可见)。
func TestShellExec_CleanEnvOnly(t *testing.T) {
	if _, err := os.Stat("/usr/bin/env"); err != nil {
		t.Skipf("无 /usr/bin/env: %v", err)
	}
	// "env" 不在白名单,验证层会拒;因此直测 execute(校验层与执行层解耦的接缝)。
	res := execute(context.Background(), 10*time.Second, "/usr/bin/env", nil)
	if res.Returncode != 0 {
		t.Fatalf("env 执行失败: %+v", res)
	}
	lines := strings.FieldsFunc(res.Stdout, func(r rune) bool { return r == '\n' })
	want := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C.UTF-8"}
	got := slices.Clone(lines)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("子进程环境 = %v, want 恰为 %v(零继承)", lines, want)
	}
}

// TestShellExec_ProcessGroupTimeout 证明:超时返回 124,且 Setpgid + 组 SIGKILL
// 消灭后台孙进程(/proc 轮询确认唯一标记时长参数的 sleep 全部消失),不遗留孤儿。
func TestShellExec_ProcessGroupTimeout(t *testing.T) {
	// 用唯一"非法"时长数字做标记:sleep 接受浮点秒数,不会像垃圾参数那样立即报错退出。
	const marker = "1234.567891"
	start := time.Now()
	// sh -c 启动两个后台 sleep:仅杀 sh 会留下孤儿;杀进程组则全部消失。
	res := execute(
		context.Background(),
		time.Second,
		"/usr/bin/sh",
		[]string{"-c", "sleep " + marker + " & sleep " + marker + " & wait"},
	)
	if res.Returncode != shellpolicy.TimeoutRejectionCode {
		t.Fatalf("超时 returncode = %d, want 124 (%+v)", res.Returncode, res)
	}
	if !strings.Contains(res.Stderr, "Command timed out after 1 seconds") {
		t.Errorf("超时消息漂移: %q", res.Stderr)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("超时回收耗时 %v,疑似僵尸/孤儿等待", elapsed)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if !procMarkerAlive(t, marker) {
			return // 全组确认死亡。
		}
		if time.Now().After(deadline) {
			t.Fatal("进程组超时后 5s 仍存活的 sleep —— 组 SIGKILL 失效")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// procMarkerAlive 扫描 /proc/*/cmdline 查找含唯一标记的进程(仅限 Linux)。
func procMarkerAlive(t *testing.T, marker string) bool {
	t.Helper()
	procs, err := filepath.Glob("/proc/[0-9]*/cmdline")
	if err != nil {
		t.Fatalf("扫描 /proc 失败: %v", err)
	}
	for _, p := range procs {
		data, err := os.ReadFile(p)
		if err != nil {
			continue // 进程刚退出:忽略竞态。
		}
		if strings.Contains(string(data), marker) {
			return true
		}
	}
	return false
}

// TestShellExec_AuditLines 验证成功与拒绝两条审计行符合 internal/audit
// 哈希链 schema(daedalus-shell 身份 + shell_exec 工具名 + outcome 派生),
// 与 daedalus-copilot / daedalus-host / daedalus-audit 等其他身份共链,
// 任何工具调用后 daedalus-audit verify 都能通过(不能断链)。
func TestShellExec_AuditLines(t *testing.T) {
	cfg := testConfig(t, "")
	session, ctx := connectSession(t, cfg)

	if _, isErr := callShell(t, session, ctx, "uname", []string{"-s"}); isErr {
		t.Fatal("uname 应成功")
	}
	if _, isErr := callShell(t, session, ctx, "rm", []string{"-rf", "/"}); !isErr {
		t.Fatal("rm 应被拒")
	}

	data, err := os.ReadFile(cfg.auditPath)
	if err != nil {
		t.Fatalf("读审计文件失败: %v", err)
	}
	lines := strings.FieldsFunc(string(data), func(r rune) bool { return r == '\n' })
	if len(lines) != 2 {
		t.Fatalf("审计行数 = %d, want 2:\n%s", len(lines), data)
	}

	// 整链验证:daedalus-audit verify 应当不报错地接受两条 entry。
	if n, err := audit.Verify(cfg.auditPath); err != nil || n != 2 {
		t.Fatalf("哈希链应通过 2 条,得 n=%d err=%v\n%s", n, err, data)
	}

	// 第一行:成功路径。顶层 schema 固定,args 嵌套对象保留原字段。
	var ok map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &ok); err != nil {
		t.Fatalf("成功审计行非法 JSON: %v\n%s", err, lines[0])
	}
	for k, want := range map[string]string{
		"identity": "daedalus-shell",
		"tool":     "shell_exec",
		"outcome":  "success",
	} {
		if got, _ := ok[k].(string); got != want {
			t.Errorf("顶层 %s 应为 %q,得 %v", k, want, ok[k])
		}
	}
	if ok["prev_hash"] == "" || ok["entry_hash"] == "" || ok["timestamp"] == "" {
		t.Errorf("哈希链字段缺失或为空: %v", ok)
	}
	// 文件行用 sort_keys=True 序列化(与 Python json.dumps(sort_keys=True)
	// 字节级兼容,保证哈希链跨语言稳定);首键是字母序最小的 args,不验
	// HasPrefix。stdout 的 IndentJSON 走插入序,那里可以验键序。
	for _, want := range []string{`"args":`, `"entry_hash":`, `"identity":`, `"outcome":`, `"policy_version":`, `"prev_hash":`, `"timestamp":`, `"tool":`} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("成功审计行缺顶层字段 %s: %s", want, lines[0])
		}
	}
	args, ok2 := ok["args"].(map[string]any)
	if !ok2 {
		t.Fatalf("args 应为对象,得 %T: %v", ok["args"], ok["args"])
	}
	if args["command"] != "uname" {
		t.Errorf("args.command 应为 uname,得 %v", args["command"])
	}
	if arr, _ := args["args"].([]any); len(arr) != 1 || arr[0] != "-s" {
		t.Errorf("args.args 应为 [-s],得 %v", args["args"])
	}
	if args["allowed"] != true {
		t.Errorf("args.allowed 应为 true,得 %v", args["allowed"])
	}
	if rc, _ := args["returncode"].(float64); rc != 0 {
		t.Errorf("args.returncode 应为 0,得 %v", args["returncode"])
	}

	// 第二行:拒绝路径。outcome=denied,command/returncode 嵌入 args。
	var bad map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &bad); err != nil {
		t.Fatalf("拒绝审计行非法 JSON: %v\n%s", err, lines[1])
	}
	if bad["outcome"] != "denied" {
		t.Errorf("拒绝行 outcome 应为 denied,得 %v", bad["outcome"])
	}
	badArgs, _ := bad["args"].(map[string]any)
	if badArgs["command"] != "rm" {
		t.Errorf("拒绝行 args.command 应为 rm,得 %v", badArgs["command"])
	}
	if badArgs["allowed"] != false {
		t.Errorf("拒绝行 args.allowed 应为 false,得 %v", badArgs["allowed"])
	}
	if rc, _ := badArgs["returncode"].(float64); rc != 126 {
		t.Errorf("拒绝行 args.returncode 应为 126,得 %v", badArgs["returncode"])
	}
}

// TestRecordAudit_CreatesFileAndChainsHash 验证 recordAudit 在文件不存在时
// 会创建文件(经 internal/audit.LogAudit 的 O_CREATE 模式),写入的 entry 立即
// 进入哈希链;并证明 1 条 entry 也能独立 verify(ts create:false 旧语义已弃用,
// 与新哈希链格式不兼容;若保留旧行为,daedalus-shell 的工具调用永远断链)。
func TestRecordAudit_CreatesFileAndChainsHash(t *testing.T) {
	cfg := serverConfig{
		allow:     shellpolicy.ResolveAllowCommands(""),
		auditPath: filepath.Join(t.TempDir(), "created-on-demand.jsonl"),
		timeout:   shellpolicy.Timeout,
	}
	res := shellExec(context.Background(), cfg, "uname", []string{"-s"})
	if res.Returncode != 0 {
		t.Errorf("审计缺失不应影响执行: %+v", res)
	}
	if _, err := os.Stat(cfg.auditPath); err != nil {
		t.Fatalf("recordAudit 应在文件缺失时创建之: %v", err)
	}
	if n, err := audit.Verify(cfg.auditPath); err != nil || n != 1 {
		t.Fatalf("新建文件 1 条 entry 哈希链应通过,得 n=%d err=%v", n, err)
	}
}

// —— policy.toml 单一事实源接线测试(计划 todo 12)——
// 经 DAEDALUS_POLICY_PATH 指向 testdata 后调用 applyPolicy,
// 断言白名单/路径规则/超时逐字跟随策略文件;测试结束还原包级默认。

// TestPolicyInjection_FollowsPolicyToml 证明策略注入端到端生效:
// 现状白名单里的 uname 被策略移除 → 126 拒绝;策略新增的 echo → 真实执行;
// blocked/前缀规则跟随 [shell] 表;超时跟随 timeout_ms。
func TestPolicyInjection_FollowsPolicyToml(t *testing.T) {
	t.Setenv(policy.EnvPolicyPath, filepath.Join("testdata", "policy.toml"))
	p, err := applyPolicy()
	if err != nil {
		t.Fatalf("applyPolicy 加载 testdata 策略失败: %v", err)
	}
	t.Cleanup(func() { shellpolicy.WithPolicy(policy.Default()) })

	if shellpolicy.Timeout != 5*time.Second {
		t.Fatalf("timeout_ms 未注入: %v, want 5s", shellpolicy.Timeout)
	}
	// 路径规则跟随策略:blocked=/root 生效,blocked=/etc/shadow 不再特殊
	//(但仍在白名单外),前缀仅 /tmp。
	if _, err := shellpolicy.ValidatePath("/root/.ssh/id_rsa"); err == nil ||
		!strings.Contains(err.Error(), "blocked path") {
		t.Errorf("策略 blocked_paths=[/root] 未生效: %v", err)
	}
	if _, err := shellpolicy.ValidatePath("/etc/shadow"); err == nil ||
		!strings.Contains(err.Error(), "outside allowed directories") {
		t.Errorf("现状 blocked 移除后应落入 outside 分支: %v", err)
	}

	cfg := serverConfig{
		allow:     policy.AllocCommands(p),
		auditPath: mustCreateAuditFile(t),
		timeout:   shellpolicy.Timeout,
	}
	res := shellExec(context.Background(), cfg, "uname", nil)
	if res.Returncode != shellpolicy.ValidationRejectionCode {
		t.Fatalf("策略移除 uname 后应 126 拒绝: %+v", res)
	}
	res = shellExec(context.Background(), cfg, "echo", []string{"policy-ok"})
	if res.Returncode != 0 || strings.TrimSpace(res.Stdout) != "policy-ok" {
		t.Fatalf("策略新增 echo 应真实执行: %+v", res)
	}
}

// TestPolicyInjection_AllowCommandsEnvReplacesPolicy 证明 ALLOW_COMMANDS
// 在"策略文件来源"之上仍维持 REPLACE(非并集)语义。
func TestPolicyInjection_AllowCommandsEnvReplacesPolicy(t *testing.T) {
	t.Setenv(policy.EnvPolicyPath, filepath.Join("testdata", "policy.toml"))
	p, err := applyPolicy()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shellpolicy.WithPolicy(policy.Default()) })
	t.Setenv(policy.EnvAllowCommands, "date")

	allow := policy.AllocCommands(p)
	if len(allow) != 1 {
		t.Fatalf("env 应整体替换为 1 项, got %v", allow)
	}
	cfg := serverConfig{allow: allow, auditPath: mustCreateAuditFile(t), timeout: shellpolicy.Timeout}
	if res := shellExec(context.Background(), cfg, "echo", nil); res.Returncode != shellpolicy.ValidationRejectionCode {
		t.Errorf("被 env 替换掉的 echo 应拒绝: %+v", res)
	}
	if res := shellExec(context.Background(), cfg, "date", nil); res.Returncode != 0 {
		t.Errorf("env 保留的 date 应放行: %+v", res)
	}
}

// TestPolicyInjection_CorruptRefusesStartup 钉死 fail-closed:
// 损坏 TOML → applyPolicy 报错,服务器 main 据此拒绝启动;
// 与"文件缺失回退 Default"严格区分。
func TestPolicyInjection_CorruptRefusesStartup(t *testing.T) {
	t.Setenv(policy.EnvPolicyPath, filepath.Join("testdata", "corrupt.toml"))
	if _, err := applyPolicy(); err == nil {
		t.Fatal("损坏策略竟然加载成功(应拒绝启动)")
	}
}

// TestPolicyInjection_MissingFallsBackToDefault 钉死稳健性要求:
// 无 policy.toml 也能启动 —— LoadOrDefault 回退 Default,
// 注入后行为与现状硬编码常量完全一致(uname 放行、rm 拒绝)。
func TestPolicyInjection_MissingFallsBackToDefault(t *testing.T) {
	t.Setenv(policy.EnvPolicyPath, filepath.Join(t.TempDir(), "absent.toml"))
	// 显式指向不存在 → 硬错误(不静默降级):
	if _, err := policy.Load(""); err == nil {
		t.Fatal("显式指向缺失应报 IO 错误")
	}
	// 显式指向不存在 → 硬错误(不静默降级):
	if _, err := policy.Load(""); err == nil {
		t.Fatal("显式指向缺失应报 IO 错误")
	}
	// 清空 env 后再验证开发态回溯不可得(chdir 到临时目录,测试结束自动还原)
	// 时的 Default 回退:
	t.Setenv(policy.EnvPolicyPath, "")
	t.Chdir(t.TempDir())
	if _, err := os.Stat(policy.ProductionPath); err == nil {
		t.Skip("本机存在生产策略,跳过缺失回退演练")
	}
	p, err := policy.LoadOrDefault()
	if err != nil {
		t.Fatalf("缺失应回退 Default: %v", err)
	}
	if len(p.Shell.AllowedCommands) != 15 {
		t.Fatalf("Default 命令数 = %d, want 15", len(p.Shell.AllowedCommands))
	}
}
