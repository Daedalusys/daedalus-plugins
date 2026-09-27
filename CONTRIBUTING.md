# Contributing to daedalus-plugins

本文档是**插件仓特有的贡献指南**。通用贡献规范（代码风格、注释语言、测试要求、commit convention、PR 流程）见 [`../daedalus-core/CONTRIBUTING.md`](../daedalus-core/CONTRIBUTING.md)。

## 本仓特有约束

### 插件布局

每个插件一个子目录，结构固定：

```
<cap>/
├── daedalus.plugin.json   # manifest（id/type/runtime/executable/tools/resources）
├── cmd/daedalus-<cap>/    # Go 源码（go-sdk stdio MCP 服务器）
├── bin/daedalus-<cap>     # 构建产物（just plugin-pack 拷入，不入库）
├── go.mod / go.sum        # module github.com/Daedalusys/daedalus-plugins/<cap>
└── i18n/                  # locale 文件（如有）
```

**blueprint 插件**另有 `blueprints/` 数据目录（6 蓝图 × 6 文件），源码侧唯一事实源。

### 命名规范

每个插件有**两个名字**，职责不同：

| 标识符 | 性质 | 用途 |
|--------|------|------|
| 目录名 / id（如 `shell/`、`daedalus.shell`） | **稳定、机器可解析** | systemd 单元、CI、import 路径、copilot 硬编码引用 |
| `name` 字段（如 `Daedalus Command Execution`） | **人类可读、可自由演进** | `daedalus-host list` / `inspect` 展示 |

**约定**: 目录名与 id 永不改；`name` 按"XX 能力"语义命名。

### 独立 Go Module

每个插件是独立 Go 模块（`module github.com/Daedalusys/daedalus-plugins/<cap>`），**不聚合到根模块**。跨插件共享代码 → 提 SDK，不要在本仓共享子包。

### 三仓平级布局

本地开发需三仓平级 clone（`go.work` 本地 dev 桥依赖兄弟仓路径）。仓名必须为 `daedalus-core` / `daedalus-sdk` / `daedalus-plugins`。

```bash
mkdir -p ~/work/daedalusys && cd ~/work/daedalusys
git clone <core> && git clone <sdk> && git clone <plugins>
cd daedalus-core && cp go.work.example go.work
just verify-dev-layout
```

## Development Workflow

### 1. 单插件开发

```bash
cd <cap>
go build ./...
go test ./...
```

### 2. 全仓测试

```bash
# 逐 cap 独立跑（仓根无 go.mod，workspace 形态下不可用）
for cap in fs shell pkg sysinfo service blueprint dupe trace proc; do
    (cd "$cap" && go build ./... && go test ./...)
done
```

### 3. SDK 变更联动

插件依赖的 SDK 包改动在 `daedalus-sdk/` 仓独立演进，本仓经 `replace` 自动跟随本地 checkout。跨仓契约由各仓漂移测试钉住。

### 4. 打包（主仓驱动）

```bash
cd ../daedalus-core
just plugin-pack   # 构建 Go + 同步 bin/ + 打 zip + 解压安装态
```

### 5. 新增插件

1. 本仓加新目录（`manifest` + `cmd/` + `go.mod`）
2. 主仓 `just plugin-pack` 循环纳入
3. `76-daedalus-plugin-gen.sh` 渲染 systemd 单元
4. 更新本 README「插件索引」表

## 反模式（本仓）

| 禁止行为 | 原因 |
|----------|------|
| 改插件目录名 / manifest `id` | 被 systemd 单元 / copilot 硬编码锁定 |
| 手改 `bin/daedalus-*` 二进制 | `just plugin-pack` 重建产物 |
| 在本仓加跨插件共享 Go 子包 | 提 SDK，根模块独立是不变约束 |
| `shell=True` / `bash -c` / `sh -c` | 直 argv exec 经 shellpolicy 校验 |
| 接受相对路径 / 空字节 / realpath 逃逸 | 必经 pathguard |
| 在 `service` 插件内改 systemd 状态 | 状态变更一律经 `daedalus-tx` |
| 手改 `cmd/daedalus-blueprint/blueprints/` | 数据源是 `blueprint/blueprints/`，`just blueprint-embed` 复制 |
| manifest `resources[].kind` 加新 Kind 不同步 SDK | `76-daedalus-plugin-gen.sh` 拒构建 |
| 独立发版本仓 | 镜像即发布物，主仓 `just build` 是唯一出口 |

## Architecture References

- [`../daedalus-core/ARCHITECTURE.md`](../daedalus-core/ARCHITECTURE.md) — 系统架构总览
- [`../daedalus-core/VISION.md`](../daedalus-core/VISION.md) — 系统愿景与设计
- [`../daedalus-core/AGENTS.md`](../daedalus-core/AGENTS.md) — AI 操作知识库
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — 插件架构说明
