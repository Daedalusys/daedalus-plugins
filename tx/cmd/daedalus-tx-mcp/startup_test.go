package main

// startup_test.go —— 启动期 fail-closed 的进程级证据:档位表读坏时 main() 必须以
// 退出码 2 拒启,而不是静默用出厂默认跑起来(否则"配置事故"会伪装成"默认更保守")。

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"testing"
)

const helperEnv = "GO_WANT_TX_STARTUP_HELPER"

// TestStartupHelperProcess 不是真用例:被上面那条用例以子进程方式召回,直接跑 main()。
func TestStartupHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		t.Skip("仅作为子进程辅助入口")
	}
	main()
}

// runHelperProcess 以子进程跑一次 main(),返回退出码;env 追加在父进程环境之后。
func runHelperProcess(t *testing.T, env []string, stderr *bytes.Buffer) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestStartupHelperProcess")
	cmd.Env = append(os.Environ(), append([]string{helperEnv + "=1"}, env...)...)
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("子进程启动失败: %v", err)
	}
	return exitErr.ExitCode()
}
