package main

// preview_test.go —— tx_preview 的判定面:三档、argv、属性快照与危险名单合流。
// 夹具一律经环境变量注入档位表/策略路径,不碰本机真实 /etc 与 /opt。

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Daedalusys/daedalus-sdk/autonomy"
)

// testPolicyTOML 能满足 policy.Load 的全部必需字段,只把危险名单固定成 sshd;
// 其余值取保守占位(真实值与本插件的判定无关)。
const testPolicyTOML = `[shell]
allowed_commands = ["systemctl"]
binary_dirs = ["/usr/bin"]
allowed_path_prefixes = ["/tmp"]
blocked_paths = ["/etc/shadow"]
clean_env = { PATH = "/usr/bin:/bin" }
timeout_ms = 1000
max_output_bytes = 1048576

[fs]
allowed_dirs = ["/tmp"]
max_read_bytes = 1048576

[audit]
log_path = "/tmp/audit.jsonl"
max_size_mb = 1
retain_days = 30

[state]
max_size_mb = 1

[objectmodel]
enabled_kinds = ["service"]

[blueprints]
output_dirs = ["/tmp"]
post_check_commands = ["true"]
reload_services = ["nginx"]
secret_sources = ["credstore"]

[fleet]
high_risk_packages = ["kernel"]
high_risk_path_prefixes = ["/etc"]
high_risk_services = ["sshd"]
high_risk_adapters = ["bootc.switch"]
transient_retry_max = 1
heartbeat_timeout_seconds = 1
`

// isolateRuntime 把两个配置注入口都指到临时目录:档位表缺失 ⇒ 出厂默认,
// 策略写一份最小可用夹具 ⇒ loadRuntime 正常返回(缺策略即拒启由专门用例覆盖)。
func isolateRuntime(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(autonomy.EnvPath, filepath.Join(dir, "agent-autonomy.toml"))
	policyPath := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(policyPath, []byte(testPolicyTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DAEDALUS_POLICY_PATH", policyPath)
}

func defaultConfig() *autonomy.Config {
	cfg := autonomy.Default()
	return &cfg
}

func TestBuildPreviewAutoWhenEnabledButNotRunning(t *testing.T) {
	cfg := defaultConfig()
	v, serr := buildPreview("started", "demo.service", domainUser, cfg,
		observation{enabled: true, running: false, known: true})
	if serr != nil {
		t.Fatalf("期望判定成功, 收到 %+v", serr)
	}
	if v.Tier != string(autonomy.TierAuto) || v.Reason != autonomy.ReasonPreset {
		t.Fatalf("期望 auto/preset, 收到 %s/%s", v.Tier, v.Reason)
	}
	if want := []string{"systemctl", "--user", "start", "demo.service"}; !reflect.DeepEqual(v.Argv, want) {
		t.Fatalf("argv = %v, 期望 %v", v.Argv, want)
	}
	if v.Scope != "systemd:user:start:demo.service" {
		t.Fatalf("scope = %q", v.Scope)
	}
	if v.Adapter != adapterServiceSet {
		t.Fatalf("adapter = %q", v.Adapter)
	}
	if len(v.RequiredScope) != 0 {
		t.Fatalf("auto 档不该要条子, required_scope = %v", v.RequiredScope)
	}
	if v.Attributes.Domain != domainUser || !v.Attributes.Known || v.Attributes.HighRisk {
		t.Fatalf("attributes = %+v", v.Attributes)
	}
}

func TestBuildPreviewConfirmCarriesRequiredScope(t *testing.T) {
	cfg := defaultConfig()
	v, serr := buildPreview("restarted", "demo.service", domainUser, cfg,
		observation{enabled: true, running: true, known: true})
	if serr != nil {
		t.Fatalf("期望判定成功, 收到 %+v", serr)
	}
	if v.Tier != string(autonomy.TierConfirm) || v.Reason != autonomy.ReasonPreset {
		t.Fatalf("期望 confirm/preset, 收到 %s/%s", v.Tier, v.Reason)
	}
	if want := []string{"systemd:user:restart:demo.service"}; !reflect.DeepEqual(v.RequiredScope, want) {
		t.Fatalf("required_scope = %v, 期望 %v", v.RequiredScope, want)
	}
	if want := []string{"systemctl", "--user", "restart", "demo.service"}; !reflect.DeepEqual(v.Argv, want) {
		t.Fatalf("argv = %v, 期望 %v", v.Argv, want)
	}
}

// 域闸门:system 域无条件第三档。域必须由调用方显式赋值 —— 这条用例同时钉住
// "没漏填 Domain"(漏填会走 fallback 而不是 domain,两者都 human 但原因不同)。
func TestBuildPreviewClassifiesSystemDomainAsHuman(t *testing.T) {
	cfg := defaultConfig()
	v, serr := buildPreview("started", "nginx.service", domainSystem, cfg,
		observation{enabled: true, running: false, known: true})
	if serr != nil {
		t.Fatalf("期望判定成功, 收到 %+v", serr)
	}
	if v.Tier != string(autonomy.TierHuman) || v.Reason != autonomy.ReasonDomain {
		t.Fatalf("期望 human/domain, 收到 %s/%s", v.Tier, v.Reason)
	}
	// system 域只出现在第三档提案里给人看:去掉 --user 才是可直接执行的形态。
	if want := []string{"systemctl", "start", "nginx.service"}; !reflect.DeepEqual(v.Argv, want) {
		t.Fatalf("argv = %v, 期望 %v", v.Argv, want)
	}
}

// 属性查不到一律第三档,用户规则也不例外(降档条件不成立)。
func TestBuildPreviewUnknownObservationIsHuman(t *testing.T) {
	cfg := defaultConfig()
	cfg.Rules = []autonomy.Rule{{Scope: "systemd:user:start:*", Tier: autonomy.TierAuto}}
	v, serr := buildPreview("started", "demo.service", domainUser, cfg, observation{})
	if serr != nil {
		t.Fatalf("期望判定成功, 收到 %+v", serr)
	}
	if v.Tier != string(autonomy.TierHuman) || v.Reason != autonomy.ReasonFallback {
		t.Fatalf("期望 human/fallback, 收到 %s/%s", v.Tier, v.Reason)
	}
	if v.Attributes.Known {
		t.Fatal("attributes.known 应如实为 false")
	}
}

func TestPreparePreviewValidation(t *testing.T) {
	cases := []struct {
		name    string
		in      previewIn
		wantErr string
		wantOur string
	}{
		{"non-service kind", previewIn{Kind: "package", Name: "nginx.service", DesiredState: "started"}, "unsupported_kind", ""},
		{"reload not in vocabulary", previewIn{Kind: "service", Name: "nginx.service", DesiredState: "reload"}, "unsupported_desired_state", ""},
		{"empty name", previewIn{Kind: "service", Name: "", DesiredState: "started"}, "invalid_name", ""},
		{"path separator", previewIn{Kind: "service", Name: "a/b.service", DesiredState: "started"}, "invalid_name", ""},
		{"leading dash", previewIn{Kind: "service", Name: "-x.service", DesiredState: "started"}, "invalid_name", ""},
		{"other unit suffix", previewIn{Kind: "service", Name: "backup.timer", DesiredState: "started"}, "invalid_name", ""},
		{"bare name rejected (no implicit suffix)", previewIn{Kind: "service", Name: "nginx", DesiredState: "started"}, "invalid_name", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unit, serr := preparePreview(tc.in)
			if tc.wantErr != "" {
				if serr == nil || serr.Error != tc.wantErr {
					t.Fatalf("期望错误 %q, 收到 %+v", tc.wantErr, serr)
				}
				return
			}
			if serr != nil {
				t.Fatalf("期望通过, 收到 %+v", serr)
			}
			if unit != tc.wantOur {
				t.Fatalf("unit = %q, 期望 %q", unit, tc.wantOur)
			}
		})
	}
}

// policy.toml 的 [fleet].high_risk_services 必须并入 deny_names:同一台机器上
// sshd 是"触即高危",而普通用户单元仍然可以走预设(auto/confirm)。
func TestHighRiskServiceFromPolicyBecomesDenyName(t *testing.T) {
	isolateRuntime(t)
	policyPath := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(policyPath, []byte(testPolicyTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DAEDALUS_POLICY_PATH", policyPath)

	cfg, err := loadRuntime(&bytes.Buffer{})
	if err != nil {
		t.Fatalf("loadRuntime: %v", err)
	}
	found := false
	for _, name := range cfg.DenyNames {
		if name == "sshd" {
			found = true
		}
	}
	if !found {
		t.Fatalf("policy 的高危名单未并入 deny_names: %v", cfg.DenyNames)
	}

	v, serr := buildPreview("started", "sshd.service", domainUser, cfg,
		observation{enabled: true, running: false, known: true})
	if serr != nil {
		t.Fatalf("期望判定成功, 收到 %+v", serr)
	}
	if v.Tier != string(autonomy.TierHuman) || v.Reason != autonomy.ReasonDeny {
		t.Fatalf("期望 human/deny, 收到 %s/%s", v.Tier, v.Reason)
	}
	if !v.Attributes.HighRisk {
		t.Fatal("attributes.high_risk 应如实为 true")
	}

	// 同一份配置下,非高危单元不因合并而失活。
	v, serr = buildPreview("started", "demo.service", domainUser, cfg,
		observation{enabled: true, running: false, known: true})
	if serr != nil {
		t.Fatalf("期望判定成功, 收到 %+v", serr)
	}
	if v.Tier != string(autonomy.TierAuto) {
		t.Fatalf("demo.service 期望 auto, 收到 %s/%s", v.Tier, v.Reason)
	}
}

// 档位表读不到 ⇒ 出厂默认(不是错误);读坏 ⇒ 错误(由调用方退 2)。
func TestLoadRuntimeAutonomyFallbackAndFailure(t *testing.T) {
	isolateRuntime(t)
	cfg, err := loadRuntime(&bytes.Buffer{})
	if err != nil {
		t.Fatalf("档位表缺失应回退出厂默认, 收到 %v", err)
	}
	if len(cfg.Presets) == 0 {
		t.Fatal("回退后应带出厂预设")
	}

	bad := filepath.Join(t.TempDir(), "agent-autonomy.toml")
	if err := os.WriteFile(bad, []byte("unknown_key = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(autonomy.EnvPath, bad)
	if _, err := loadRuntime(&bytes.Buffer{}); err == nil {
		t.Fatal("档位表含未知键必须报错(fail-closed), 不能静默退默认")
	}
}

// 危险名单是必需输入:policy.toml 缺失 ⇒ 拒绝启动(退出码 2),不是"只告警继续"。
func TestPluginRefusesToStartOnMissingPolicy(t *testing.T) {
	dir := t.TempDir()
	var stderr bytes.Buffer
	code := runHelperProcess(t, []string{
		autonomy.EnvPath + "=" + filepath.Join(dir, "agent-autonomy.toml"),
		"DAEDALUS_POLICY_PATH=" + filepath.Join(dir, "policy.toml"),
	}, &stderr)
	if code != exitStartupFailure {
		t.Fatalf("退出码 = %d, 期望 %d", code, exitStartupFailure)
	}
	if !strings.Contains(stderr.String(), "危险名单不可用") || !strings.Contains(stderr.String(), "拒绝启动") {
		t.Fatalf("stderr 未说明拒启原因: %q", stderr.String())
	}
}

// 策略文件损坏(未知键)与缺失同归 fail-closed:严格加载失败 ⇒ 退出码 2。
func TestPluginRefusesToStartOnBrokenPolicy(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(broken, []byte(testPolicyTOML+"unknown_key = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	code := runHelperProcess(t, []string{
		autonomy.EnvPath + "=" + filepath.Join(dir, "agent-autonomy.toml"),
		"DAEDALUS_POLICY_PATH=" + broken,
	}, &stderr)
	if code != exitStartupFailure {
		t.Fatalf("退出码 = %d, 期望 %d", code, exitStartupFailure)
	}
	if !strings.Contains(stderr.String(), "危险名单不可用") || !strings.Contains(stderr.String(), "拒绝启动") {
		t.Fatalf("stderr 未说明拒启原因: %q", stderr.String())
	}
}

// 启动期拒启是进程行为:用子进程跑 main(),断言退出码 2。这里给出可用的策略,
// 让失败只能归因于档位表 —— 否则策略缺失会先一步把进程拦下,用例就测不到本意。
func TestPluginRefusesToStartOnBadAutonomyFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "agent-autonomy.toml")
	if err := os.WriteFile(bad, []byte("[[rule]]\nscope = \"systemd:user:start:*\"\ntier = \"auto\"\nbogus = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	goodPolicy := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(goodPolicy, []byte(testPolicyTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	code := runHelperProcess(t, []string{
		autonomy.EnvPath + "=" + bad,
		"DAEDALUS_POLICY_PATH=" + goodPolicy,
	}, &stderr)
	if code != exitStartupFailure {
		t.Fatalf("退出码 = %d, 期望 %d", code, exitStartupFailure)
	}
	if !strings.Contains(stderr.String(), "启动失败") {
		t.Fatalf("stderr 未说明拒启原因: %q", stderr.String())
	}
}

// observeUnit 只接受"rc=0 + known=true + enabled/running 齐全"的观测,其余一律
// 折成查不到(半份观测比没有观测更危险)。
func TestObserveUnitFailsClosedOnIncompleteObservation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want observation
	}{
		{
			name: "完整观测",
			body: `printf '%s\n' '{"enabled":true,"running":false,"known":true}'`,
			want: observation{enabled: true, running: false, known: true},
		},
		{
			name: "缺 enabled",
			body: `printf '%s\n' '{"running":false,"known":true}'`,
			want: observation{},
		},
		{
			name: "known=false",
			body: `printf '%s\n' '{"enabled":true,"running":false,"known":false}'`,
			want: observation{},
		},
		{
			name: "rc 非零",
			body: `printf '%s\n' '{"enabled":true,"running":false,"known":true}'; exit 1`,
			want: observation{},
		},
		{
			name: "坏 JSON",
			body: `printf '%s\n' 'unknown unit'`,
			want: observation{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installFakeTxScript(t, tc.body)
			if got := observeUnit("demo.service"); got != tc.want {
				t.Fatalf("observation = %+v, 期望 %+v", got, tc.want)
			}
		})
	}
}

// 进程级故障(二进制不存在)同样是查不到,不是工具错误。
func TestObserveUnitFailsClosedWhenBinaryMissing(t *testing.T) {
	old := txBinary
	txBinary = filepath.Join(t.TempDir(), "daedalus-tx")
	t.Cleanup(func() { txBinary = old })
	if got := observeUnit("demo.service"); got != (observation{}) {
		t.Fatalf("observation = %+v, 期望零值", got)
	}
}

func TestRunTxPassesArgvVerbatim(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "calls.log")
	installFakeTxScript(t, `printf '%s\n' "$*" >> "$TX_CALL_LOG"`)
	t.Setenv("TX_CALL_LOG", logPath)
	if _, _, rc, err := runTx("service-observe", "--unit", "demo.service"); err != nil || rc != 0 {
		t.Fatalf("runTx: rc=%d err=%v", rc, err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != "service-observe --unit demo.service" {
		t.Fatalf("argv = %q", got)
	}
}

// installFakeTxScript 把 txBinary 换成一段 shell 脚本:生产代码绝不经过 shell,
// 但测试夹具用 shell 最省事。
func installFakeTxScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "daedalus-tx")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := txBinary
	txBinary = path
	t.Cleanup(func() { txBinary = old })
	return path
}
