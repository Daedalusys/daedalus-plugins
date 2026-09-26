// Command daedalus-shell 是 shell 能力 MCP 服务器(stdio JSON-RPC)。
//
// 行为规格源:shell_server.ts(生产实现)。提供唯一工具 shell_exec:命令与参数
// 经 internal/shellpolicy 白名单校验后,用 os/exec **argv 直发**执行(绝不经过
// sh -c),环境仅 CLEAN_ENV 两项(绝不继承),30 秒超时对整个进程组 SIGKILL。
// 拒绝语义与 ts shellExec 一致:验证失败返回结果对象(126)而非协议错误。
//
// 策略来源:白名单/路径/环境/超时启动时从 shared/policy.toml 读取并注入
// shellpolicy;文件缺失或损坏一律拒绝启动(fail-closed,回退 Default 需
// DAEDALUS_POLICY_MODE=development 显式 opt-in);
// ALLOW_COMMANDS 环境变量保持 REPLACE(整体替换)语义。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Daedalusys/daedalus-sdk/audit"
	"github.com/Daedalusys/daedalus-sdk/policy"
	"github.com/Daedalusys/daedalus-sdk/shellpolicy"
	"github.com/Daedalusys/daedalus-sdk/version"
)

// serverName 为 Go 版服务器标识;Go 实现用无 -deno 后缀的名字。
const serverName = "daedalus-shell"

// waitGracePeriod 对应 os/exec 的 WaitDelay:SIGKILL 后若孙进程仍持有管道,
// 最长再等这么久强制关闭 I/O,保证 Wait 必然返回、不产生僵尸。
const waitGracePeriod = 2 * time.Second

// serverConfig 收敛 shell 服务器的可注入依赖;main 从环境解析一次,测试直接
// 构造以避免进程级 env 竞态。
type serverConfig struct {
	allow     map[string]struct{}
	auditPath string
	timeout   time.Duration
}

// shellExecIn 对应 shell_server.ts 的 inputSchema:command 必填,args 可选。
type shellExecIn struct {
	Command string   `json:"command" jsonschema:"The command name to execute (must be in ALLOW_COMMANDS)."`
	Args    []string `json:"args,omitempty" jsonschema:"List of command-line arguments to pass."`
}

// execResult 对应 ts ShellExecResult:字段顺序即 JSON 键顺序,与 JSON.stringify
// 输出逐字一致;成功路径 error 键整体缺省(对应 ts 的 undefined 被省略)。
type execResult struct {
	Stdout     string  `json:"stdout"`
	Stderr     string  `json:"stderr"`
	Returncode int     `json:"returncode"`
	Error      *string `json:"error,omitempty"`
}

// auditEntry 对应 ts recordAudit 的 JSON 键顺序与可空性:returncode/error 恒在。
type auditEntry struct {
	Timestamp  float64  `json:"timestamp"`
	Tool       string   `json:"tool"`
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	Allowed    bool     `json:"allowed"`
	Returncode *int     `json:"returncode"`
	Error      *string  `json:"error"`
}

func main() {
	// 单一事实源:启动时读 shared/policy.toml 并注入 shellpolicy。缺失/损坏/字段
	// 缺失一律 fail-closed → 拒绝启动(仅 development opt-in 才回退 Default())。
	p, err := applyPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}

	cfg := serverConfig{
		// ALLOW_COMMANDS 环境变量维持 REPLACE 语义(整体替换,非并集)。
		allow:     policy.AllocCommands(p),
		auditPath: auditPath(p),
		timeout:   shellpolicy.Timeout,
	}
	server := newServer(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !isCleanShutdown(err) {
		fmt.Fprintf(os.Stderr, "%s server error: %v\n", serverName, err)
		os.Exit(1)
	}
}

// applyPolicy 加载策略(缺失默认 fail-closed,development opt-in 才回退
// Default)并注入 shellpolicy 包级常量,使
// 白名单/路径前缀/blocked 清单/净化环境/超时全部跟随 policy.toml;与测试共用
// 同一入口(测试经 DAEDALUS_POLICY_PATH 指向 testdata)。
func applyPolicy() (*policy.Policy, error) {
	p, err := policy.LoadOrDefault()
	if err != nil {
		return nil, fmt.Errorf("policy load failed, refusing to start: %w", err)
	}
	shellpolicy.WithPolicy(p)
	return p, nil
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

// auditPath 解析审计日志落点:DAEDALUS_AUDIT_LOG_PATH 环境变量优先(与
// shell_server.ts 现状语义一致,保持调用方兼容),其次取 [audit].log_path。
func auditPath(p *policy.Policy) string {
	if v := os.Getenv(shellpolicy.AuditPathEnv); v != "" {
		return v
	}
	return p.Audit.LogPath
}

// newServer 注册唯一的 shell_exec 工具(注解逐字对应 shell_server.ts)。
func newServer(cfg serverConfig) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, nil)

	nonDestructive := false
	closedWorld := false

	mcp.AddTool(server, &mcp.Tool{
		Name: "shell_exec",
		Description: "Execute an allowlisted command with arguments safely (read-only / diagnostic). " +
			"Restricted to an argv allowlist with strict argument path validation and 30s timeout.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: &nonDestructive,
			IdempotentHint:  true,
			OpenWorldHint:   &closedWorld,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in shellExecIn) (*mcp.CallToolResult, any, error) {
		// 与 ts 一致:Array 之外一律视作空参数列表。
		if in.Args == nil {
			in.Args = []string{}
		}
		res := shellExec(ctx, cfg, in.Command, in.Args)
		encoded, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return nil, nil, fmt.Errorf("序列化执行结果失败: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(encoded)}},
			// 与 ts 同:isError 由退出码决定。
			IsError: res.Returncode != 0,
		}, nil, nil
	})

	return server
}

// shellExec 逐分支移植 shell_server.ts shellExec:先命令、后参数,任一验证失败
// → 审计(allowed=false, 126)并返回 126;超时 → 124;启动失败 → 1;
// 正常执行 → 实际退出码(后三者审计均为 allowed=true)。
func shellExec(ctx context.Context, cfg serverConfig, command string, args []string) execResult {
	if args == nil {
		args = []string{}
	}

	cmdToRun, err := shellpolicy.ValidateCommand(command, cfg.allow)
	if err != nil {
		return reject(cfg, command, args, "Command validation failed", err)
	}
	for _, arg := range args {
		if err := shellpolicy.ValidateArg(arg); err != nil {
			return reject(cfg, command, args, "Argument validation failed", err)
		}
	}

	res := execute(ctx, cfg.timeout, cmdToRun, args)
	// execute 恰好在超时与启动失败时设置 Error 字段,直接以其作为 error 载荷
	// 即与 ts 逐分支等价。
	rc := res.Returncode
	recordAudit(cfg.auditPath, newAuditEntry(command, args, true, &rc, res.Error))
	return res
}

func reject(cfg serverConfig, command string, args []string, prefix string, cause error) execResult {
	msg := cause.Error()
	rc := shellpolicy.ValidationRejectionCode
	recordAudit(cfg.auditPath, newAuditEntry(command, args, false, &rc, &msg))
	return execResult{
		Stdout:     "",
		Stderr:     fmt.Sprintf("%s: %s", prefix, msg),
		Returncode: rc,
		Error:      &msg,
	}
}

// execute 用 os/exec 以 argv 直发运行命令(绝不经过 sh -c)。分支语义:成功
// (含非零退出)回传真实退出码;截止到达 → 124;无法启动 → 1 + "Execution
// failed: " 前缀。
func execute(ctx context.Context, timeout time.Duration, cmdToRun string, args []string) execResult {
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, cmdToRun, args...)
	cmd.Env = shellpolicy.CleanEnv // 整体替换:零继承环境变量。
	// 独立进程组 + Cancel 时对组长 SIGKILL:超时后整组消灭,不留孤儿。
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// 进程可能已退出(ESRCH 忽略);恒返回 nil,避免污染 Wait 的错误语义。
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return nil
	}
	cmd.WaitDelay = waitGracePeriod

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	switch {
	case runErr == nil:
		return execResult{Stdout: stdout.String(), Stderr: stderr.String(), Returncode: cmd.ProcessState.ExitCode()}

	case errors.Is(execCtx.Err(), context.DeadlineExceeded):
		// 与 ts 同:SIGKILL 后 stdout 丢弃,消息含超时秒数。
		msg := fmt.Sprintf("Command timed out after %d seconds", int(timeout/time.Second))
		return execResult{Stdout: "", Stderr: msg, Returncode: shellpolicy.TimeoutRejectionCode, Error: &msg}

	default:
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) && exitErr.ExitCode() >= 0 {
			// 正常退出但非零:与 ts 一致回传真实退出码,不判为错误分支。
			return execResult{Stdout: stdout.String(), Stderr: stderr.String(), Returncode: exitErr.ExitCode()}
		}
		// 与 ts 外层 catch 同:启动/等待失败 → "Execution failed: ..." + 1。
		msg := runErr.Error()
		return execResult{
			Stdout:     "",
			Stderr:     fmt.Sprintf("Execution failed: %s", msg),
			Returncode: shellpolicy.ExecutionFailureCode,
			Error:      &msg,
		}
	}
}

func newAuditEntry(command string, args []string, allowed bool, returncode *int, errMsg *string) auditEntry {
	return auditEntry{
		Timestamp:  float64(time.Now().UnixNano()) / float64(time.Second),
		Tool:       "shell_exec",
		Command:    command,
		Args:       args,
		Allowed:    allowed,
		Returncode: returncode,
		Error:      errMsg,
	}
}

// recordAudit best-effort 追加一条哈希链审计条目(经 internal/audit.LogAudit,
// O_CREATE|O_APPEND,写失败一律静默)。daedalus-shell 必须与其他身份共链,不能
// 跳过 LogAudit 走简写 JSON。args 字段以 JSON 对象嵌入 audit.Entry.Args,
// identity 固定 "daedalus-shell",tool 固定 "shell_exec";outcome 由 Allowed
// 派生:允许执行 → "success",验证拒绝 → "denied"。
func recordAudit(path string, entry auditEntry) {
	outcome := "success"
	if !entry.Allowed {
		outcome = "denied"
	}
	// 用临时 struct 序列化保证字段顺序与键名稳定,再经 audit.ParseValue 解析为
	// *audit.Value,由 LogAudit 走 sort_keys + ensure_ascii 规范化,字节级兼容
	// Python audit-log.py。
	argsJSON, err := json.Marshal(struct {
		Command    string   `json:"command"`
		Args       []string `json:"args,omitempty"`
		Allowed    bool     `json:"allowed"`
		Returncode *int     `json:"returncode"`
		Error      *string  `json:"error,omitempty"`
	}{
		Command:    entry.Command,
		Args:       entry.Args,
		Allowed:    entry.Allowed,
		Returncode: entry.Returncode,
		Error:      entry.Error,
	})
	if err != nil {
		return
	}
	argsVal, err := audit.ParseValue(string(argsJSON))
	if err != nil {
		argsVal = audit.NewObject() // 解析失败兜底空对象,不让审计阻塞 exec
	}
	_, _ = audit.LogAudit(audit.Entry{
		Identity: "daedalus-shell",
		Tool:     "shell_exec",
		Args:     argsVal,
		Outcome:  outcome,
		LogPath:  path,
	})
}
