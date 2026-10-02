# daedalus-plugins — 17 个 Go 能力插件 monorepo

四层结构(决策 23/24 + 25)中的**插件层**:17 个 Go 能力插件(capability,
runtime=native)的 monorepo,独立仓根。copilot 插件(Deno)留主仓
`daedalus-core/plugin/copilot/`,不在此仓。

每个插件一个子目录,内含 `daedalus.plugin.json`(manifest)+ `cmd/`(Go 源码)+
`bin/`(构建产物,`just plugin-pack` 拷入,不入库)。各插件独立 `go.mod`
(`module github.com/Daedalusys/daedalus-plugins/<cap>`),经
`replace github.com/Daedalusys/daedalus-sdk => ../daedalus-sdk` 引用 SDK(该路径为
插件仓 CI 形状;本地三仓平级布局由主仓 `daedalus-core/go.work` 的 replace 覆盖)。
仓根 `go.work` 聚合各插件模块。

## 插件索引

| 插件 | id | MCP 工具 | 依赖 SDK 包 | 说明 |
|------|----|----------|-------------|------|
| `fs/` | `daedalus.fs` | `read_file` / `write_file` / `list_dir` / `move_file` | `pathguard` | 路径作用域文件读写;ALLOWED_DIRS 前缀边界 + realpath 防逃逸 |
| `shell/` | `daedalus.shell` | `shell_exec` | `shellpolicy` | 15 命令白名单 / 4 bin 目录 / 路径规则;CLEAN_ENV、30s、rc 126/124;零 `/bin/sh` 包装 |
| `pkg/` | `daedalus.pkg` | `dnf_query` / `dnf_list_installed` | `pkgquery` | dnf/rpm 只读查询(rpm 优先、dnf repoquery 兜底);声明 `resources`(`kind: package`) |
| `sysinfo/` | `daedalus.sysinfo` | `os_release` / `hardware_info` / `network_status` | `sysinfo` | os-release / cpuinfo / meminfo / 网络只读探测 |
| `service/` | `daedalus.service` | `service.query` / `service.list` | `objectmodel`、`state`、`dirs` | systemd 单元只读观测;唯一声明 `resources`(`kind: service`)的官方插件;状态变更一律走 `daedalus-tx` |
| `blueprint/` | `daedalus.blueprint` | `blueprint_list` / `blueprint_inspect` / `blueprint_render` / `blueprint_apply` / `blueprint_status` / `blueprint_remove` | `blueprint`、`shellpolicy`(post_check 钩子) | 6 个参数化配置蓝图(nginx/postgres/redis/haproxy);数据经 `//go:embed` 编入二进制,源码侧 `blueprints/` 是唯一事实源 |
| `dupe/` | `daedalus.dupe` | `scan_large` / `scan_dupes` | `pathguard` | 大文件 + 重复文件只读扫描(L0);未走 release 供料(zip 仍经 `-verify --keep`) |
| `trace/` | `daedalus.trace` | `trace_session` / `trace_tool` / `trace_tx` / `trace_summary` | `audit` | audit.jsonl 哈希链回放只读视图(L0,游标分页);未走 release 供料 |
| `proc/` | `daedalus.proc` | `proc_list` / `proc_tree` / `proc_fds` / `proc_listen` / `proc_cgroup` | —(直读 `/proc`) | 进程/fd/监听端口/cgroup 只读侦察(L0,零 exec);未走 release 供料 |
| `hwmon/` | `daedalus.hwmon` | `hwmon_temperatures` / `hwmon_fans` / `hwmon_voltages` / `hwmon_power` / `hwmon_battery` / `hwmon_thermal_zones` | `pathguard` | `/sys/class/hwmon` 等 sysfs L0 传感器只读 |
| `journal/` | `daedalus.journal` | `journal_query` / `journal_follow` / `journal_last_boot` | `version` | `journalctl` L0 查询/跟随/last-boot;缺 CLI 优雅降级 |
| `triage/` | `daedalus.triage` | `boot_blame` / `boot_critical_chain` / `last_boot_log` / `coredumps_list` / `coredump_info` | `version` | `systemd-analyze` / `coredumpctl` / `journalctl` L0 启动归因 + 关键链 + 崩溃 |
| `integrity/` | `daedalus.integrity` | `rpm_verify` / `rpm_unchanged` / `rpm_summary` | `version` | `rpm -V` L0 完整性校验(游标分页防 OOM) |
| `avc/` | `daedalus.avc` | `avc_recent` / `avc_explain` / `avc_summary` | `version` | `ausearch` / `audit2why` / `audit2allow` L0 SELinux AVC 拒访查询 |
| `gpu/` | `daedalus.gpu` | `gpu_list` / `gpu_status` / `gpu_processes` / `gpu_memory` | `version` | `nvidia-smi` / `rocm-smi` / `nvtop` / `intel_gpu_top` L0 GPU 遥测 |
| `smart/` | `daedalus.smart` | `smart_list` / `smart_health` / `smart_attributes` / `smart_test` | `version` | `smartctl` L0 磁盘 SMART 健康(只读) |
| `search/` | `daedalus.search` | `search_files` / `search_content` / `search_reindex` | `version` | Baloo L0 文件/内容检索 + 索引重建;D-Bus session-reachability spike 门禁 |

## 命名语义(目录名 ≠ 系统组件,是"能力提供者")

> 用户反馈"命名容易让人摸不着头脑"——`shell/` 不是 shell 本身,`service/` 不是
> systemd 服务。本节澄清两个标识符的分工。

每个插件有**两个名字**,职责不同、互不替代:

| 标识符 | 例子 | 性质 | 用途 |
|--------|------|------|------|
| **目录名 / id**(技术标识符) | `shell/`、`daedalus.shell` | **稳定、机器可解析** | systemd 单元名、CI、import 路径、copilot 硬编码引用、`daedalus-host` 发现/校验——**改动即破坏全链路** |
| **`name` 字段**(显示名) | `Daedalus Command Execution` | **人类可读、可自由演进** | `daedalus-host list` / `inspect` 展示、UI 呈现——只影响展示,不影响任何机器行为 |

**目录名是技术标识符,`name` 是显示名,两者分离的原因**:技术标识符一旦发布就被
systemd 单元、CI、import 路径、copilot 硬编码引用锁定,改名成本极高且无功能收益;
显示名则随时可以按"能力语义"调整,让人类一眼看懂这个插件**提供什么能力**。

17 个插件目录名 → 实际能力对照(目录名 ≠ 系统组件):

| 目录名 / id | 显示名(`name`) | 实际能力(不是……) |
|-------------|----------------|--------------------|
| `fs/` (`daedalus.fs`) | Daedalus Filesystem Access | 路径作用域文件读写能力——**不是**文件系统本身 |
| `shell/` (`daedalus.shell`) | Daedalus Command Execution | 受控命令执行能力(15 命令白名单沙箱)——**不是** shell 解释器 |
| `pkg/` (`daedalus.pkg`) | Daedalus Package Query | dnf/rpm 只读包查询能力——**不是**包管理器 |
| `sysinfo/` (`daedalus.sysinfo`) | Daedalus System Information | 只读系统信息探测能力 |
| `service/` (`daedalus.service`) | Daedalus Service Query | 只读服务状态查询能力——**不是** systemd 服务,也不改服务状态(状态变更走 `daedalus-tx`) |
| `blueprint/` (`daedalus.blueprint`) | Daedalus Blueprint | 参数化配置蓝图渲染/应用能力 |
| `dupe/` (`daedalus.dupe`) | Daedalus Duplicate & Large File Scanner | 大文件 + 重复文件只读扫描——**不是**删除工具(删除走 `daedalus.disk-clean`) |
| `trace/` (`daedalus.trace`) | Daedalus Audit Trace View | audit.jsonl 哈希链回放只读视图——**不是**重放执行(那是 030 workflow) |
| `proc/` (`daedalus.proc`) | Daedalus Process Inspector | 进程/fd/监听端口/cgroup 只读侦察——**不是**进程控制(kill/signal/renice 走 `daedalus-tx`) |
| `hwmon/` (`daedalus.hwmon`) | Daedalus Hardware Sensors | `/sys/class/hwmon` 等 sysfs 传感器只读——**不是**硬件控制(write 一律 `NEVER`) |
| `journal/` (`daedalus.journal`) | Daedalus Journal Query | `journalctl` 只读查询/跟随——**不是**日志写入(审计走 `daedalus-audit`) |
| `triage/` (`daedalus.triage`) | Daedalus Boot & Crash Triage | 启动归因 + 关键链 + 崩溃记录——**不是**启动修复 |
| `integrity/` (`daedalus.integrity`) | Daedalus Integrity Verification | `rpm -V` 完整性校验——**不是**包修复(写走 `daedalus-tx package.set`) |
| `avc/` (`daedalus.avc`) | Daedalus SELinux AVC Denial Query | `ausearch`/`audit2why`/`audit2allow` SELinux 拒访查询——**不是** SELinux 策略修改 |
| `gpu/` (`daedalus.gpu`) | Daedalus GPU Telemetry | GPU 遥测(显卡/状态/进程/显存)——**不是** GPU 调度或性能调优 |
| `smart/` (`daedalus.smart`) | Daedalus SMART Health | `smartctl` 磁盘健康只读——**不是** SMART 自检触发(写型 `--test=` 不放) |
| `search/` (`daedalus.search`) | Daedalus File Search | Baloo 文件/内容检索 + 索引重建——**不是** 全文引擎管理 |

**约定**:目录名与 id 永不改;显示名 `name` 按"XX 能力"语义命名,改动只影响展示层。

## 目录布局(以 `fs/` 为例)

```
fs/
├── daedalus.plugin.json      # manifest(id/type/runtime/executable/tools/resources/permissions)
├── cmd/daedalus-fs/          # Go 源码(go-sdk stdio MCP 服务器)
├── bin/daedalus-fs           # 构建产物(just plugin-pack 拷入;不入库)
├── go.mod / go.sum           # module github.com/Daedalusys/daedalus-plugins/fs
└── i18n/                     # locale 文件(如有)
```

`blueprint/` 另有 `blueprints/` 数据目录(6 蓝图 × 6 文件,源码侧唯一事实源;
构建期经 `just blueprint-embed` rsync 到 `cmd/daedalus-blueprint/blueprints/`
供 `//go:embed`,复制产物不入库)。

## 跨仓 release 流程

插件仓不独立发布——发布以**主仓镜像构建**为出口,插件仓只演进源码:

1. **改插件源码**(本仓 `cmd/` 或 manifest)→ 本仓 `go build ./...` + `go test ./...`
   自检(依赖 SDK 经 `replace` 指向平级 `daedalus-sdk/`,3 仓须平级 clone);
2. **SDK 变更联动**:插件依赖的 SDK 包改动在 `daedalus-sdk/` 仓独立演进,
   插件仓经 `replace` 自动跟随本地 checkout;跨仓契约由
   `tests/deno/shellpolicy_contract.test.ts`(Go↔Deno)与各仓漂移测试钉住;
3. **打包**:主仓 `just plugin-pack` —— 构建全部 Go 二进制 → 同步到
   `daedalus-plugins/<cap>/bin/` → `daedalus-plugin-pack` 打 zip(注入逐条目
   sha256 checksums + manifest 规范化自摘要)→ `-verify --keep` 解压到镜像树
   安装态 `daedalus-core/files/system/opt/daedalus/plugins/daedalus.<cap>/`;
4. **构建期自校验**:`76-daedalus-plugin-gen.sh` 从 manifest + policy.toml 渲染
   systemd ExecStart,交叉核对 `tools` 与二进制 stdio `tools/list`、`resources[].kind`
   ⊆ `[objectmodel].enabled_kinds`,漂移即拒构建;
5. **镜像出口**:主仓 `just build`(sync + podman build)→ 镜像内 15 插件
   (copilot + 14 能力,dupe/trace/proc 仅 TMPDIR 校验不入安装态)全 ok 断言在 v3 构建机补跑(plan todo 18)。

**版本策略**:插件 manifest `version` 与 SDK 包版本各自演进;插件仓不产
独立 release artifact,镜像即发布物。

## 开发与测试

```bash
cd daedalus-plugins && go build ./... && go test ./...   # 17 插件全量
```

- 包内注释一律中文(仓库根 CONVENTIONS)。
- 本仓不产镜像产物;安装态由主仓 `just plugin-pack` 生成,勿手改
  `daedalus-core/files/system/opt/daedalus/plugins/`。
- 新增插件 = 本仓加新目录(manifest + cmd/ + bin/)→ 主仓 `just plugin-pack`
  循环纳入 → `76-daedalus-plugin-gen.sh` 渲染 systemd 单元。
## Where to file issues

请在新仓开 issue。本 issue tracker **仅服务本仓代码**：
- 跨仓问题（如同时影响 SDK 与 plugins）请先开在本仓，影响面大者会在评论里 cross-link 到其他仓。
- 老仓 `Daedalusys/Daedalusys` 已于 2026-09-21 archived，历史 issue 保留可读；新 issue 一律开在本仓。
