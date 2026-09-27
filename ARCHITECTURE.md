# Architecture

> 面向新贡献者的插件系统架构总览。操作流程与硬性约定见 [AGENTS.md](AGENTS.md)，
> 插件索引与命名语义见 [README.md](README.md)，两者与本文互补、不重复。

## Overview

daedalus-plugins 是 Daedalus 四层结构中的**插件层**，9 个 Go 能力插件的 monorepo，独立仓根。
每个插件占一个子目录、一个独立 Go module（`module github.com/Daedalusys/daedalus-plugins/<cap>`），
实现一个 capability server：以 Model Context Protocol (MCP) over stdio 暴露一组 tools，由宿主
`daedalus-host` 发现与校验、systemd 按构建期渲染的 ExecStart 直接拉起。插件发布形态是 zip 归档
（二进制 + manifest + SHA-256 checksums），随镜像发布，本仓只演进源码、不产独立 release。

一次调用在整条链路上的走向：

```
LLM / Agent Client / copilot 插件
        │  JSON-RPC over stdio (MCP)
        ▼
daedalus.<cap>   (本仓 Go 静态二进制, runtime=native)
  ├─ cmd/daedalus-<cap>/main.go    go-sdk stdio server, 注册 tools
  └─ 工具实现 → daedalus-sdk 强制执行层 (pathguard / shellpolicy / policy)
        │                                │
        ▼                                ▼
  audit.jsonl (哈希链证据)          systemd 沙箱 (DynamicUser + Landlock + seccomp)
```

## Plugin System

### MCP Protocol

- **传输**: Model Context Protocol，JSON-RPC over stdio transport。每个插件二进制是
  `modelcontextprotocol/go-sdk` 的 stdio server，进程内零网络监听。
- **能力面**: 每个插件是一个 capability server，只暴露 manifest `tools[]` 声明的工具。
  构建期 `76-daedalus-plugin-gen.sh`（主仓）交叉核对 `tools[]` 与二进制 stdio `tools/list`
  的返回，漂移即拒构建。
- **宿主角色**: `daedalus-host` 提供 `list` / `inspect` / `verify` / `run-plugin` / `render-unit`
  五个子命令，负责发现、校验与构造启动命令。宿主**不是**任何 MCP server 的父进程、零 spawn，
  `run-plugin` 只打印命令，真正执行者是 systemd。
- **审计面**: 每次工具调用经 `daedalus-sdk/audit` 落哈希链审计日志，宿主操作同样写 `host_*` 条目，
  任何绕过该入口的写入都被视为违规。
- **一次调用的生命周期**: `initialize` 握手协商协议版本 → 客户端发 `tools/list` 拉工具清单
  （与 manifest `tools[]` 一致）→ `tools/call` 携带 JSON schema 描述的结构化参数 → 服务器
  侧经 SDK 做策略与路径校验 → 执行并返回结果 → 同步写一条审计条目。全程无原始 shell
  字符串拼接，参数以类型化字段传递。

### Plugin Format

zip 归档由主仓的 `daedalus-plugin-pack` 产出，条目只有 manifest 与二进制，不携带源码：

```
daedalus.<cap>.plugin.zip
├── daedalus.plugin.json   # manifest（pack 注入 checksums + 规范化自摘要）
└── bin/daedalus-<cap>     # Go 静态二进制
```

manifest 关键字段（源码侧 `<cap>/daedalus.plugin.json` 是唯一事实源）：

| Field | Example | 说明 |
|-------|---------|------|
| `id` | `daedalus.fs` | 稳定机器标识，与目录名绑定，改动即破坏全链路 |
| `name` | `Daedalus Filesystem Access` | 人类可读显示名，只影响展示层 |
| `version` | `0.1.0` | 插件版本，与 SDK 包版本各自演进 |
| `type` | `capability` | 本仓 9 个插件全部是 capability 类型 |
| `runtime` | `native` | Go 静态二进制运行时（copilot 的 deno 运行时不在本仓） |
| `executable` | `bin/daedalus-fs` | 相对路径，需可执行位 |
| `tools` | `read_file`, `write_file` | 对外暴露的 MCP 工具清单 |
| `permissions` | `read` / `write` 路径数组 | 声明式能力边界，运行时由 pathguard 等强制执行 |
| `resources` | `{ kind: service, name: * }` | 资源声明，目前仅 `service` 与 `pkg` 两个插件写 |
| `checksums` | 逐条目 sha256 | pack 阶段注入，源码侧 manifest 不含，缺它宿主校验会 degraded |

打包与校验的几条硬性质：

- **可复现**: 条目时间戳固定为 1980-01-01、按字典序写入，同一输入必得同一 zip。
- **zip-slip 防线**: 解包拒绝 `..` 段、绝对路径、符号链接、重复条目与 zip-bomb 体积异常。
- **暂存目录打包**: 只把 manifest 与 `bin/` 拷进暂存目录再打包，源码与测试数据绝不进 zip。
- **解压即校验**: `-verify --keep` 边解压边核对逐条目 sha256 与 manifest 自摘要，落盘即完整。

### Security Boundaries

每个插件进程由 systemd 单元直接执行，沙箱是多层叠加的：

- **DynamicUser**: 每插件独立动态用户（`DynamicUser=yes` + `ProtectSystem=strict`），
  进程无持久身份，插件之间互不相通。
- **Landlock**: `.service.d/landlock.conf` drop-in 挂 Landlock LSM，按路径粒度收窄可触达的目录树。
- **seccomp**: 同一 drop-in 内 `SystemCallFilter=@system-service`，显式拒绝 `@privileged`
  等敏感 syscall 类，配合 `MemoryDenyWriteExecute`。
- **pathguard**: 文件系统类工具的路径必经 `daedalus-sdk/pathguard` 校验，按
  `policy.toml [fs].allowed_dirs` 做前缀边界检查，拒绝相对路径、空字节与 realpath 逃逸。
- **policy 单一事实源**: `shared/policy.toml` 由 `daedalus-sdk/policy` 在启动时严格加载，
  损坏或缺失一律 fail-closed 拒启；shell 白名单（15 命令 / 4 bin 目录）由 `shellpolicy`
  强制执行，且零 `/bin/sh` 包装。
- **构建期防线**: `76-daedalus-plugin-gen.sh` 渲染 ExecStart 时核对沙箱语义，
  单元主体与 landlock / credentials drop-in 必须原样存在，任一漂移即拒构建。

## Plugin Inventory

| Plugin | Purpose | Key Tools | Policy Level |
|--------|---------|-----------|--------------|
| `fs` | Filesystem operations（路径作用域文件读写） | `read_file`, `write_file`, `list_dir`, `move_file` | R2 |
| `shell` | Shell command execution（15 命令白名单沙箱） | `shell_exec` | R1 (dangerous) |
| `pkg` | Package management（dnf/rpm 只读查询） | `dnf_query`, `dnf_list_installed` | R2 |
| `sysinfo` | System information（OS/hardware/network 探测） | `os_release`, `hardware_info`, `network_status` | R1 |
| `service` | systemd service management（单元只读观测） | `service.query`, `service.list`, `systemd_failed`, `systemd_timer_next`, `systemd_dependencies` | R2 |
| `blueprint` | Blueprint rendering（6 参数化配置蓝图） | `blueprint_list`, `blueprint_inspect`, `blueprint_render`, `blueprint_apply`, `blueprint_status`, `blueprint_remove` | R2 |
| `dupe` | Duplicate file detection（大文件与重复文件扫描） | `scan_large`, `scan_dupes` | R2 |
| `trace` | Trace/log analysis（审计链回放只读视图） | `trace_session`, `trace_tool`, `trace_tx`, `trace_summary` | R1 |
| `proc` | Process management（进程只读侦察） | `proc_list`, `proc_tree`, `proc_fds`, `proc_listen`, `proc_cgroup` | R2 |

Policy Level 为策略档位标记（R1 / R2），仅作分档参考；运行时真正强制执行的值
以 `policy.toml` 与各插件 systemd 沙箱配置为准。前 6 个插件是出厂件，`dupe` / `trace` / `proc`
三个观测型插件尚未走 release 供料。

贯穿全表的一条边界是**只读与变更的分离**：插件工具只做观测与渲染，凡是改变系统状态的操作
（service 状态、package 安装、蓝图落盘）一律经 `daedalus-tx` 事务通道提交，绕过即破坏审计链。
`trace` / `proc` 更进一步，全程零 exec、直读 `/proc` 与审计日志。

## Build Pipeline

本仓没有根 `go.mod`，构建、打包、校验三步要么按独立模块跑，要么由主仓驱动：

- **全量构建**: CI `test.yml` 同款逐 cap 循环，`cd <cap> && go build -o bin/ ./cmd/...` 后跑
  `go test ./...`；单个插件也可单独构建，互不阻塞。
- **打包**: `daedalus-plugin-pack -in <暂存目录> -out <zip>` 从暂存目录（只放 manifest 与 `bin/`）
  打 zip 并注入逐条目 sha256 checksums；入口是主仓 `just plugin-pack`，本仓 `release.yml`
  在 `v*` tag 上自行构建并上传 zip 资产。
- **校验**: `daedalus-plugin-pack -verify <zip> --keep <dest>` 解压即校验；安装态用
  `daedalus-host -dir <dir> verify <id>` 核对 manifest 与 checksums，degraded 插件会被
  `run-plugin` / `render-unit` 拒绝。
- **独立 go.mod**: 每插件 `module github.com/Daedalusys/daedalus-plugins/<cap>`，经
  `replace github.com/Daedalusys/daedalus-sdk => ../daedalus-sdk` 引用 SDK（该路径是 CI 形状）；
  仓根 `go.work` 聚合 9 个模块，跨插件共享代码一律提 SDK、不在本仓开共享子包。
- **蓝图数据**: `blueprint` 构建前需把 `blueprints/` rsync 到 `cmd/daedalus-blueprint/blueprints/`
  供 `//go:embed`，本地与 CI 都先做这一步再编译。

## Directory Structure

```
daedalus-plugins/
├── go.work                     # 聚合 9 个插件模块 (use .)
├── fs/                         # daedalus.fs
│   ├── daedalus.plugin.json    # manifest（唯一事实源，不含 checksums）
│   ├── cmd/daedalus-fs/        # Go 源码：main.go + 工具实现 + *_test.go
│   ├── bin/daedalus-fs         # 构建产物（just plugin-pack 拷入，不入库）
│   ├── go.mod / go.sum         # 独立模块定义
│   └── i18n/                   # locale 文件（如有）
├── shell/  pkg/  sysinfo/  service/  ...   # 其余插件同构
└── blueprint/
    ├── blueprints/             # 蓝图数据（6 蓝图 × 5 文件，//go:embed 源）
    └── cmd/daedalus-blueprint/blueprints/  # 构建期复制产物，不入库
```

- 入口是 `cmd/daedalus-<cap>/main.go`：go-sdk stdio server 在此注册 tools，其余实现文件与测试
  平铺在同一目录，没有独立 `tools/` 子包。
- 蓝图数据的单一事实源是源码侧 `blueprint/blueprints/<id>/`，构建期副本只供 embed，
  改蓝图只改前者。

## SDK Dependencies

插件之间不共享代码，通用逻辑全部下沉到 `../daedalus-sdk`：

| Package | 用途 | 主要消费方 |
|---------|------|-----------|
| `objectmodel/` | Resource model 类型（Kind 封闭枚举 + Object 信封） | `service` |
| `pathguard/` | 文件系统路径沙箱（前缀边界 + realpath 防逃逸） | `fs`, `dupe` |
| `shellpolicy/` | Shell 命令白名单策略（15 命令 / 4 bin 目录 / 路径规则） | `shell`, `blueprint`（post_check 钩子） |
| `pkgquery/` | 包管理器查询抽象（rpm 优先，dnf repoquery 兜底） | `pkg` |
| `sysinfo/` | 系统信息采集（os-release / cpuinfo / meminfo / 网络） | `sysinfo` |
| `dirs/` | state/tx 根路径统一解析链 | `service` |
| `blueprint/` | 蓝图类型定义与 schema 校验 | `blueprint` |
| `i18n/` | 国际化 locale 资源（Go 侧接线预留） | manifest `i18n` 声明 |
| `audit/` | 哈希链审计写入（唯一合规入口） | 全部 9 个插件 |
| `policy/` | `policy.toml` 严格加载（fail-closed） | `fs`, `shell`, `blueprint`, `dupe` |
| `state/` | 追加式观测缓存（派生层，与审计分离） | `service` |
| `version/` | 版本信息 | 全部 9 个插件 |

新增依赖的规则很简单：先在 SDK 开包并钉契约，再让插件 `import`，本仓永远不长出共享子包。

## Reference

- 运行时、打包与镜像细节: `../daedalus-core/AGENTS.md`
- SDK 契约、威胁面与策略包: `../daedalus-sdk/AGENTS.md`
- 插件格式规范: 主仓 `plugin/README.md` 与 `../daedalus-sdk/plugin/`
