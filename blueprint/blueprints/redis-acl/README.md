# Redis ACL 用户蓝图 (redis-acl)

添加或修改 Redis ACL 用户,输出 ACL 规则文件到
`/etc/redis/daedalus/{user}.acl`,reload `redis` 服务。

## 用途

- 创建 ACL 用户 `app1`,允许 `GET` / `SET` / `DEL` 命令与全部键。
- 用户已存在时更新其密码与权限。

## 输入参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `user` | string | ✔ | — | ACL 用户名,`^[a-zA-Z0-9_-]+$` |
| `password` | string | ✔ | — | 密码,**仅接受 `secret://` 引用**(如 `secret://kwallet/redis/app1`),不落明文 |
| `allowed_commands` | string[] | ✘ | `[GET, SET, DEL]` | 允许的命令列表 |
| `allowed_keys` | string[] | ✘ | `["*"]` | 允许的键模式(glob) |

## 输出

- ACL 文件:`/etc/redis/daedalus/{user}.acl`
- reload 服务:`redis`
- post_check:`redis-cli ACL GETUSER {user}`

## Copilot 使用示例

```text
创建 Redis ACL 用户 app1,密码从 kwallet 的 redis/app1 取,只允许 GET SET DEL,键范围 app1:*
```

或显式指定参数:

```json
{
  "user": "app1",
  "password": "secret://kwallet/redis/app1",
  "allowed_commands": ["GET", "SET", "DEL"],
  "allowed_keys": ["app1:*"]
}
```

## 说明

- `password` 必须为 `secret://` 引用,蓝图插件解析后注入 ACL 规则,**明文密码直接拒绝**。
- 模板用 `{{- range .allowed_commands }}` / `{{- range .allowed_keys }}` 循环生成
  `+<命令>` / `~<键模式>` 规则;模板含 `{{/* INSERTION_POINT */}}` 插入点,
  可追加 `-@dangerous` 类别排除、`&<通道模式>` 订阅授权等。
