// config.go —— 启动期配置:档位表 + 危险名单。两者各读一次,运行期不再重读
// (档位表改动的生效边界就是进程重启,避免同一进程内规则前后不一致)。
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
	"github.com/Daedalusys/daedalus-sdk/policy"
)

// loadRuntime 读档位表与危险名单并合流。档位表读坏 ⇒ error(调用方以退出码 2
// 拒启);策略文件不可用 ⇒ 只保留档位表自带的 deny_names 并告警 —— 危险名单
// 缺失只会让判定更严,不会放宽,因此不值得让整个写通道拒绝启动。
func loadRuntime(stderr io.Writer) (*autonomy.Config, error) {
	cfg, err := autonomy.LoadConfigured()
	switch {
	case err == nil:
	case errors.Is(err, autonomy.ErrNotFound):
		def := autonomy.Default()
		cfg = &def
	default:
		return nil, err
	}

	p, perr := policy.Load(policyPath())
	if perr != nil {
		fmt.Fprintf(stderr, "%s: 策略不可用,危险名单未合并(仅用档位表 deny_names): %v\n", serverName, perr)
		return cfg, nil
	}
	// [fleet].high_risk_services 与档位表 deny_names 同一语义(裸名前缀),
	// 合流后由 Classify 的第一道闸门统一处理。
	cfg.DenyNames = append(cfg.DenyNames, p.Fleet.HighRiskServices...)
	return cfg, nil
}

// policyPath 只认显式注入口与镜像内生产路径,不做 cwd 回溯:危险名单决定
// 「哪些对象 AI 永远不能自主动」,不能因为当前目录恰好有个测试策略文件就变。
func policyPath() string {
	if p := os.Getenv(policy.EnvPolicyPath); p != "" {
		return p
	}
	return policy.ProductionPath
}
