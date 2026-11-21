// exec.go —— core 的 daedalus-tx CLI 直 argv 封装。
//
// 绝不经过 sh -c:参数按切片直发,单元名在源头已过字符集门,不存在 shell 解释面。
// txBinary 是包级变量:生产用安装路径,测试替换成假 CLI。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// txBinary 是 core CLI 的安装路径。用绝对路径而非 PATH 查找:宿主环境变量不可信,
// PATH 被改就能把"受控变更"指到任意二进制。
var txBinary = "/usr/local/bin/daedalus-tx"

// txTimeout 是单次 CLI 调用的上限:观测卡住时不能让 MCP 会话跟着挂死。
const txTimeout = 15 * time.Second

// runTx 直发一次 CLI 调用。rc 是 CLI 的业务退出码;err 只表示进程级故障
// (起不来 / 超时 / 被信号杀),两者分开,调用方才能区分"CLI 说查不到"与
// "CLI 根本跑不起来"。
func runTx(args ...string) (stdout, stderr string, rc int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), txTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, txBinary, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	runErr := cmd.Run()
	if runErr == nil {
		return outBuf.String(), errBuf.String(), 0, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return outBuf.String(), errBuf.String(), -1, fmt.Errorf("daedalus-tx 超时/取消: %w", ctxErr)
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return outBuf.String(), errBuf.String(), exitErr.ExitCode(), nil
	}
	return outBuf.String(), errBuf.String(), -1, runErr
}

// txIDPattern 与 core CLI 的形状门逐字一致:16 位小写十六进制。CLI 的 stdout 也按
// 此校验 —— 一个不合格的 tx-id 拼进下一步 argv 就是在猜事务。
var txIDPattern = regexp.MustCompile(`^[a-f0-9]{16}$`)

// serviceSetStep 是 service.set 的步骤 args:两键锁定 schema。用结构体而非 map,
// 键序稳定(propose 的 argv 逐字可复现),且不会顺手多写一个键被适配器拒绝。
type serviceSetStep struct {
	Name         string `json:"name"`
	DesiredState string `json:"desired_state"`
}

// runServiceSetTransaction 走完 core CLI 的三步事务:begin → propose → apply。
// 返回 tx-id 供审计串接。任何一步失败都返回错误:部分成功的事务不能当成功报告,
// 调用方读 tx-status 去查实际状态。
func runServiceSetTransaction(unit, desiredState string) (string, error) {
	stdout, stderrText, rc, err := runTx("begin")
	if err != nil {
		return "", fmt.Errorf("daedalus-tx begin 进程故障: %w", err)
	}
	if rc != 0 {
		return "", cliFailure("begin", rc, stdout, stderrText)
	}
	var begin struct {
		TxID string `json:"tx_id"`
	}
	if err := json.Unmarshal([]byte(stdout), &begin); err != nil {
		return "", fmt.Errorf("daedalus-tx begin 的输出不是 JSON: %w", err)
	}
	if !txIDPattern.MatchString(begin.TxID) {
		return "", fmt.Errorf("daedalus-tx begin 返回的 tx_id 非法: %q", begin.TxID)
	}

	stepJSON, err := json.Marshal(serviceSetStep{Name: unit, DesiredState: desiredState})
	if err != nil {
		return "", fmt.Errorf("序列化 service.set 参数失败: %w", err)
	}
	stdout, stderrText, rc, err = runTx("propose", begin.TxID, adapterServiceSet, string(stepJSON))
	if err != nil {
		return "", fmt.Errorf("daedalus-tx propose 进程故障: %w", err)
	}
	if rc != 0 {
		return "", cliFailure("propose", rc, stdout, stderrText)
	}

	stdout, stderrText, rc, err = runTx("apply", begin.TxID)
	if err != nil {
		return "", fmt.Errorf("daedalus-tx apply 进程故障: %w", err)
	}
	if rc != 0 {
		return "", cliFailure("apply", rc, stdout, stderrText)
	}
	return begin.TxID, nil
}

// cliFailure 把 CLI 的 {"error":...} 转成 Go 错误。只取 error 字段,不回灌整份
// stdout/stderr:事务日志全文可能很长,而且会顺着工具错误进入客户端日志。
func cliFailure(sub string, rc int, stdout, stderrText string) error {
	var doc struct {
		Error string `json:"error"`
	}
	msg := ""
	if err := json.Unmarshal([]byte(stdout), &doc); err == nil {
		msg = doc.Error
	}
	if msg == "" {
		msg = strings.TrimSpace(stderrText)
	}
	if msg == "" {
		return fmt.Errorf("daedalus-tx %s 失败(rc=%d)", sub, rc)
	}
	return fmt.Errorf("daedalus-tx %s 失败(rc=%d): %s", sub, rc, truncateRunes(msg, 240))
}
