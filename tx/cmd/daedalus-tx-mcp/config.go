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

// loadRuntime 读档位表与危险名单并合流。两者都是必需输入:任一不可用 ⇒ error,
// 调用方以退出码 2 拒启。
//
// 危险名单不能降级成"只告警":缺名单时出厂预设会把一个 enabled && !running 的
// 高危单元(如 sshd.service)判成 auto,AI 就在"名单读不到"的机器上自主变更了,
// 而客户端只看得到一条 stderr —— 拒启是唯一不留这条缝的形态。
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
		// 先落 stderr:拒绝启动是这条边唯一的人工可见信号,措辞要能直接指向裁决。
		fmt.Fprintf(stderr, "%s: 危险名单不可用 ⇒ 拒绝启动(AI 不得在缺名单时自主变更): %v\n", serverName, perr)
		return nil, fmt.Errorf("危险名单不可用: %w", perr)
	}
	// 审计与判定同读一份策略:同一身份分裂写进多条链会让 verify 必判断链。
	policyAuditLogPath = p.Audit.LogPath
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
