# daedalus-plugins — Knowledge Base

**Generated:** 2026-09-21
**Repo:** `github.com/Daedalusys/daedalus-plugins/<cap>` (6 子模块 monorepo)
**Siblings:** `../daedalus-core/` (Daedalusys, runtime + image), `../daedalus-sdk/` (11 安全核心包)

## OVERVIEW
Daedalus 插件仓根 = 四层结构中的**插件层**(决策 23/24 + 25)。6 个官方 Go 能力插件
(`fs` / `shell` / `pkg` / `sysinfo` / `service` / `blueprint`,`runtime=native`) 的 monorepo,
独立仓根。**copilot 插件**(Deno) 留主仓 `../daedalus-core/plugin/copilot/`,**不在此仓**。

每个插件一个子目录、内含 `daedalus.plugin.json` (manifest) + `cmd/` (Go 源码) +
`bin/` (构建产物,`just plugin-pack` 拷入,**不入库**)。各插件**独立 `go.mod`**
(`module github.com/Daedalusys/daedalus-plugins/<cap>`),经
`replace github.com/Daedalusys/daedalus-sdk => ../../daedalus-sdk` 引用 SDK;
仓根 `go.work` 聚合 6 个模块。

## STRUCTURE
```
daedalus-plugins/
├── go.work                          # 聚合 6 个插件模块 (use .)
├── fs/                              # daedalus.fs  - 路径作用域文件读写
│   ├── daedalus.plugin.json
│   ├── cmd/daedalus-fs/             # Go 源码 (go-sdk stdio MCP 服务器)
│   ├── bin/daedalus-fs              # 构建产物 (just plugin-pack 拷入;不入库)
│   ├── go.mod                       # module github.com/Daedalusys/daedalus-plugins/fs
│   ├── go.sum
│   └── i18n/                        # locale 文件 (如有)
├── shell/                           # daedalus.shell - 15 命令白名单
├── pkg/                             # daedalus.pkg - dnf/rpm 只读查询
├── sysinfo/                         # daedalus.sysinfo - OS/hardware/network
├── service/                         # daedalus.service - systemd 单元只读观测
└── blueprint/                       # daedalus.blueprint - 6 配置蓝图
    └── blueprints/                  # ★ 数据目录 (6 蓝图 × 6 文件; //go:embed 源)
        ├── nginx-vhost/
        ├── nginx-reverse-proxy/
        ├── postgres-db/
        ├── postgres-user/
        ├── redis-acl/
        └── haproxy-backend/
        # 每目录: manifest.json + schema.json + template.tmpl +
        #         pre_check.sh + post_check.sh + README.md
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| fs 路径读写实现 | `fs/cmd/daedalus-fs/` | 调 `daedalus-sdk/pathguard` |
| shell 命令白名单实现 | `shell/cmd/daedalus-shell/` | 调 `daedalus-sdk/shellpolicy`;15 命令 / 4 bin 目录 |
| pkg 包查询实现 | `pkg/cmd/daedalus-pkg/` | 调 `daedalus-sdk/pkgquery`;声明 `resources[].kind=package` |
| sysinfo 系统探测 | `sysinfo/cmd/daedalus-sysinfo/` | 调 `daedalus-sdk/sysinfo` |
| service 只读观测 | `service/cmd/daedalus-service/` | 调 `daedalus-sdk/{objectmodel,state,dirs}`;状态变更走 `daedalus-tx` |
| 蓝图渲染 + 应用 | `blueprint/cmd/daedalus-blueprint/` | 调 `daedalus-sdk/blueprint` + `shellpolicy` post_check 钩子 |
| 蓝图数据(参数化模板) | `blueprint/blueprints/<id>/` | `//go:embed` 源;主仓 `just blueprint-embed` rsync 到 `cmd/.../blueprints/` |
| 插件 manifest schema | `*/daedalus.plugin.json` | id/type/runtime/executable/tools/resources/permissions/i18n |
| 跨仓 SDK 引用 | 各插件 `go.mod` 的 `replace` | `=> ../../daedalus-sdk`;三仓平级 clone 时优先走 `../daedalus-core/go.work` |

## 插件索引

| 插件 | id | MCP 工具 | 依赖 SDK 包 | 实际能力(不是……) |
|------|----|----------|-------------|--------------------|
| `fs/` | `daedalus.fs` | `read_file` / `write_file` / `list_dir` / `move_file` | `pathguard` | 路径作用域文件读写 — **不是**文件系统本身 |
| `shell/` | `daedalus.shell` | `shell_exec` | `shellpolicy` | 受控命令执行 (15 命令白名单沙箱) — **不是** shell 解释器 |
| `pkg/` | `daedalus.pkg` | `dnf_query` / `dnf_list_installed` | `pkgquery` | dnf/rpm 只读包查询 — **不是**包管理器 |
| `sysinfo/` | `daedalus.sysinfo` | `os_release` / `hardware_info` / `network_status` | `sysinfo` | OS/hardware/network 只读探测 |
| `service/` | `daedalus.service` | `service.query` / `service.list` | `objectmodel`、`state`、`dirs` | systemd 单元只读观测 — **不是** systemd 服务,也不改服务状态(走 `daedalus-tx`) |
| `blueprint/` | `daedalus.blueprint` | `blueprint_list` / `blueprint_inspect` / `blueprint_render` / `blueprint_apply` / `blueprint_status` / `blueprint_remove` | `blueprint`、`shellpolicy` (post_check 钩子) | 6 参数化配置蓝图 (nginx/postgres/redis/haproxy) 渲染/应用 |
| `dupe/` | `daedalus.dupe` | `scan_large` / `scan_dupes` | `pathguard` | 大文件 + 重复文件只读扫描 (L0) — **不是** 删除工具(删除走 `daedalus.disk-clean`) |

## 命名语义 (目录名 ≠ 系统组件,是"能力提供者")

每个插件**两个名字**,职责不同、互不替代:

| 标识符 | 例子 | 性质 | 用途 |
|--------|------|------|------|
| **目录名 / id** | `shell/`、`daedalus.shell` | **稳定、机器可解析** | systemd 单元、CI、import 路径、copilot 硬编码引用 — **改动即破坏全链路** |
| **`name` 字段** | `Daedalus Command Execution` | **人类可读、可自由演进** | `daedalus-host list` / `inspect` 展示 — 只影响展示层 |

**约定**: 目录名与 id 永不改;`name` 按"XX 能力"语义命名。

## CONVENTIONS
- **注释语言(强制)**: 本仓全部 `.go` / `daedalus.plugin.json` 注释字段 / `template.tmpl` / `*.sh` 注释**必须中文**。标识符 / 字符串字面量 / JSON 键 / HTTP 头保留英文。
- **插件布局统一**: 每个 `<cap>/` = `daedalus.plugin.json` + `cmd/daedalus-<cap>/` + `bin/daedalus-<cap>` + `go.mod` + `go.sum` (+ 可选 `i18n/`,`blueprint/` 独有 `blueprints/`)。
- **独立 go.mod**: 每插件 `module github.com/Daedalusys/daedalus-plugins/<cap>`,**不聚合到根模块**;跨插件共享代码 → 提 SDK,不要在本仓共享子包。
- **跨仓 dev 桥**: 各插件 `go.work.example` (`use ( . ../../daedalus-sdk )`) 是单仓 clone 兜底;三仓平级 clone 时由 `../daedalus-core/go.work` 解析优先于各仓 `replace`。
- **不产独立 release**: 本仓只演进源码;镜像即发布物,经主仓 `just build` 出口。`bin/` 不入库,`just plugin-pack` 拷入。
- **Blueprint 数据单一事实源**: `blueprint/blueprints/<id>/` 是唯一权威;主仓 `just blueprint-embed` rsync 到 `cmd/daedalus-blueprint/blueprints/` 供 `//go:embed`,**复制产物不入库**。
- **manifest `resources`**: `service` 和 `pkg` 两个插件声明 `resources[]` (`kind=service` / `kind=package`),其余 4 个不写。`name="*"` 匹配所有资源。
- **i18n**: locale 文件在 `<cap>/i18n/<locale>.json` (POSIX 下划线命名);manifest 声明 `"i18n": ["en_US", "zh_CN"]` 数组,en_US 必定位兜底。

## 跨仓 release 流程

插件仓不独立发布 — 发布以**主仓镜像构建**为出口:

1. **改插件源码**(本仓 `cmd/` 或 manifest) → 本仓 `go build ./...` + `go test ./...` 自检;
2. **SDK 变更联动**: 插件依赖的 SDK 包改动在 `../daedalus-sdk/` 独立演进,本仓经 `replace` 自动跟随本地 checkout;跨仓契约由各仓漂移测试钉住;
3. **打包**: 主仓 `just plugin-pack` → 构建全部 Go 二进制 → 同步到本仓各 `<cap>/bin/` → `daedalus-plugin-pack` 打 zip(注入逐条目 sha256 checksums + manifest 规范化自摘要)→ `-verify --keep` 解压到镜像树安装态;
4. **构建期自校验**: `76-daedalus-plugin-gen.sh`(主仓)从 manifest + policy.toml 渲染 systemd ExecStart,交叉核对 `tools` 与二进制 stdio `tools/list`、`resources[].kind` ⊆ `[objectmodel].enabled_kinds`,漂移即拒构建;
5. **镜像出口**: 主仓 `just build` (sync + podman build) → 镜像内 7 插件(copilot + 6 能力)全 ok 断言在 v3 构建机补跑。

## ANTI-PATTERNS (THIS REPO)
- **NEVER** 改插件目录名 / manifest `id` — 被 systemd 单元 / copilot 硬编码锁定;改名即破坏全链路,只能改 `name` 显示字段。
- **NEVER** 手改 `bin/daedalus-*` 二进制 — `just plugin-pack` 重建产物,手改会被下次构建覆盖。
- **NEVER** 在本仓加跨插件共享 Go 子包 — 提 SDK,根模块独立是不变约束。
- **NEVER** `shell=True` / `bash -c` / `sh -c` — 直 argv exec 经 `daedalus-sdk/shellpolicy` 校验,无 shell 包装。
- **NEVER** 接受相对路径 / 空字节 / realpath 逃逸 — 必经 `daedalus-sdk/pathguard`。
- **NEVER** 在 `service` 插件内改 systemd 单元状态 — 状态变更一律经 `daedalus-tx` (`service.set`),绕行破坏审计链。
- **NEVER** 手改 `cmd/daedalus-blueprint/blueprints/` — 数据源是 `blueprint/blueprints/`,`just blueprint-embed` 复制,不入库。
- **NEVER** 在 manifest `resources[].kind` 加新 Kind 而不同步 `daedalus-sdk/objectmodel/` + `policy.toml` — `76-daedalus-plugin-gen.sh` 拒构建。
- **NEVER** 独立发版本仓 — 镜像即发布物,主仓 `just build` 是唯一出口。

## COMMANDS
```bash
# 单插件构建/测试
cd fs && go build ./... && go test ./...
cd shell && go build ./... && go test ./...
cd blueprint && go build ./... && go test ./...

# 全仓构建/测试 (走 go.work 聚合)
cd daedalus-plugins && go build ./... && go test ./...

# 单仓 clone (无兄弟仓): 启用 go.work
cp go.work.example go.work
cd fs && cp go.work.example go.work   # 各插件仓独立可工作

# 三仓平级 clone (推荐): 由 ../daedalus-core/go.work 桥接,无需本仓 go.work
# 仓名必须为 daedalus-core / daedalus-sdk / daedalus-plugins (与 go.work 路径对应)

# 打包 (主仓驱动,本仓只演进源码)
cd ../daedalus-core && just plugin-pack        # 构建 Go + 同步 bin/ + 打 zip + 解压安装态
cd ../daedalus-core && just blueprint-embed    # rsync blueprints/* → cmd/.../blueprints/ (//go:embed 源)

# 验证 manifest + checksums
daedalus-host -dir <unpacked-plugin-dir> verify daedalus.fs
```

## NOTES
- **跨仓契约钉子**: Go↔Deno 跨语言契约 (`tests/deno/shellpolicy_contract.test.ts` 在主仓) + 各仓漂移测试 (三点防漂移链) 是 SDK / Copilot / 插件三方同步的强制约束。
- **Blueprint 数据双源陷阱**: 源码侧 `blueprint/blueprints/` 与构建侧 `cmd/daedalus-blueprint/blueprints/` (//go:embed 目标) **同名目录**但职责不同 — 前者是单一事实源,后者是构建期复制产物(不入库);改蓝图**只改前者**,跑 `just blueprint-embed` 重生后者。
- **service 资源范围**: `service` 插件是**唯一**声明 `resources[].kind=service` 的官方插件,作用域 `name=*` 匹配所有 systemd 单元;新增资源 Kind 必经 `daedalus-sdk/objectmodel`。
- **本仓非发行版**: 无独立 release artifact,无版本 tag 发布;镜像即发布物。
- 老仓 `Daedalusys/Daedalusys` 已于 2026-09-21 archived,历史 issue 保留可读;新 issue 一律开在本仓。