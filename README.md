# daedalus-plugins — 6 个 Go 能力插件 monorepo

四层结构(决策 23/24 + 25)中的**插件层**:6 个官方 Go 能力插件(capability,
runtime=native)的 monorepo,独立仓根。copilot 插件(Deno)留主仓
`daedalus-core/plugin/copilot/`,不在此仓。

每个插件一个子目录,内含 `daedalus.plugin.json`(manifest)+ `cmd/`(Go 源码)+
`bin/`(构建产物,`just plugin-pack` 拷入,不入库)。各插件独立 `go.mod`
(`module github.com/Daedalusys/daedalus-plugins/<cap>`),经
`replace github.com/Daedalusys/daedalus-sdk => ../../daedalus-sdk` 引用 SDK;
仓根 `go.work` 聚合 6 个模块。

## 插件索引

| 插件 | id | MCP 工具 | 依赖 SDK 包 | 说明 |
|------|----|----------|-------------|------|
| `fs/` | `daedalus.fs` | `read_file` / `write_file` / `list_dir` / `move_file` | `pathguard` | 路径作用域文件读写;ALLOWED_DIRS 前缀边界 + realpath 防逃逸 |
| `shell/` | `daedalus.shell` | `shell_exec` | `shellpolicy` | 15 命令白名单 / 4 bin 目录 / 路径规则;CLEAN_ENV、30s、rc 126/124;零 `/bin/sh` 包装 |
| `pkg/` | `daedalus.pkg` | `dnf_query` / `dnf_list_installed` | `pkgquery` | dnf/rpm 只读查询(rpm 优先、dnf repoquery 兜底);声明 `resources`(`kind: package`) |
| `sysinfo/` | `daedalus.sysinfo` | `os_release` / `hardware_info` / `network_status` | `sysinfo` | os-release / cpuinfo / meminfo / 网络只读探测 |
| `service/` | `daedalus.service` | `service.query` / `service.list` | `objectmodel`、`state`、`dirs` | systemd 单元只读观测;唯一声明 `resources`(`kind: service`)的官方插件;状态变更一律走 `daedalus-tx` |
| `blueprint/` | `daedalus.blueprint` | `blueprint_list` / `blueprint_inspect` / `blueprint_render` / `blueprint_apply` / `blueprint_status` / `blueprint_remove` | `blueprint`、`shellpolicy`(post_check 钩子) | 6 个参数化配置蓝图(nginx/postgres/redis/haproxy);数据经 `//go:embed` 编入二进制,源码侧 `blueprints/` 是唯一事实源 |

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
5. **镜像出口**:主仓 `just build`(sync + podman build)→ 镜像内 7 插件
   (copilot + 6 能力)全 ok 断言在 v3 构建机补跑(plan todo 18)。

**版本策略**:插件 manifest `version` 与 SDK 包版本各自演进;插件仓不产
独立 release artifact,镜像即发布物。

## 开发与测试

```bash
cd daedalus-plugins && go build ./... && go test ./...   # 6 插件全量
```

- 包内注释一律中文(仓库根 CONVENTIONS)。
- 本仓不产镜像产物;安装态由主仓 `just plugin-pack` 生成,勿手改
  `daedalus-core/files/system/opt/daedalus/plugins/`。
- 新增插件 = 本仓加新目录(manifest + cmd/ + bin/)→ 主仓 `just plugin-pack`
  循环纳入 → `76-daedalus-plugin-gen.sh` 渲染 systemd 单元。