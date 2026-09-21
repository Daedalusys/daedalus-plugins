# HAProxy backend 蓝图 (haproxy-backend)

添加 HAProxy `backend` + `frontend` 配置段,输出独立 `.cfg` 片段到
`/etc/haproxy/daedalus/{name}.cfg`(由主配置 include),reload `haproxy` 服务。

## 用途

- 为 `api` 添加一个后端服务器池(多个上游)与监听端口的前端。
- 主配置 `/etc/haproxy/haproxy.cfg` 需 include `/etc/haproxy/daedalus/*.cfg`。

## 输入参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | ✔ | backend/frontend 标识名,`^[a-z0-9-]+$` |
| `backend_servers` | string[] | ✔ | 后端服务器地址列表(uri),如 `http://10.0.0.1:8080` |
| `frontend_port` | int | ✔ | frontend 监听端口,1-65535 |

## 输出

- 配置文件:`/etc/haproxy/daedalus/{name}.cfg`
- reload 服务:`haproxy`
- post_check:`haproxy -c -f /etc/haproxy/haproxy.cfg`

## Copilot 使用示例

```text
添加一个 HAProxy backend 叫 api,后端服务器 10.0.0.1:8080 和 10.0.0.2:8080,前端端口 8000
```

或显式指定参数:

```json
{
  "name": "api",
  "backend_servers": ["http://10.0.0.1:8080", "http://10.0.0.2:8080"],
  "frontend_port": 8000
}
```

## 说明

- 模板用 `{{- range $i, $srv := .backend_servers }}` 循环生成 `server` 行。
- 模板含 `{{/* INSERTION_POINT */}}` 插入点,可追加 ACL 路由 / ssl 终止指令。
- pre_check / post_check 均走 `haproxy -c -f` 对主配置做语法校验。
