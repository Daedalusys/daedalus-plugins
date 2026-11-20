// exec.go —— core 的 daedalus-tx CLI 直 argv 封装。
//
// 绝不经过 sh -c:参数按切片直发,单元名在源头已过字符集门,不存在 shell 解释面。
// txBinary 是包级变量:生产用安装路径,测试替换成假 CLI。
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
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
