# PostgreSQL 用户与权限蓝图 (postgres-user)

添加或修改 PostgreSQL 用户及其对指定数据库的权限,输出 SQL 脚本到
`/etc/postgresql/daedalus/{user}-{db}.sql`,reload `postgresql` 服务。

## 用途

- 创建用户 `alice`,授予其在数据库 `mydb` 上的 `SELECT` / `INSERT` 权限。
- 用户已存在时仅更新密码并补齐权限。

## 输入参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `user` | string | ✔ | 用户名,`^[a-z_][a-z0-9_]*$` |
| `password` | string | ✔ | 密码,**仅接受 `secret://` 引用**(如 `secret://kwallet/postgres/alice`),不落明文 |
| `privileges` | string[] | ✔ | 权限列表,枚举 `SELECT` / `INSERT` / `UPDATE` / `DELETE` / `ALL` |
| `db` | string | ✔ | 权限生效的数据库名,`^[a-z_][a-z0-9_]*$` |

## 输出

- SQL 脚本:`/etc/postgresql/daedalus/{user}-{db}.sql`
- reload 服务:`postgresql`
- post_check:`psql` `\du` 列表包含目标用户

## Copilot 使用示例

```text
创建 PostgreSQL 用户 alice,密码从 kwallet 的 postgres/alice 取,授予 mydb 的 SELECT 和 INSERT 权限
```

或显式指定参数:

```json
{
  "user": "alice",
  "password": "secret://kwallet/postgres/alice",
  "privileges": ["SELECT", "INSERT"],
  "db": "mydb"
}
```

## 说明

- `password` 必须为 `secret://` 引用,蓝图插件解析后注入 SQL,**明文密码直接拒绝**。
- 模板用 `{{- range .privileges }}` 循环生成逐权限 GRANT;模板含
  `{{/* INSERTION_POINT */}}` 插入点,可追加表级/列级授权。
