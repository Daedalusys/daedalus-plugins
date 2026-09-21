# PostgreSQL 数据库蓝图 (postgres-db)

创建 PostgreSQL 数据库及 owner 用户,输出 SQL 脚本到
`/etc/postgresql/daedalus/{db_name}.sql`,reload `postgresql` 服务。

## 用途

- 创建数据库 `mydb`,owner 为 `alice`。
- 幂等:数据库/用户已存在时跳过创建,仅补齐授权。

## 输入参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `db_name` | string | ✔ | 数据库名,`^[a-z_][a-z0-9_]*$` |
| `owner` | string | ✔ | owner 用户名,`^[a-z_][a-z0-9_]*$` |
| `password` | string | ✔ | 密码,**仅接受 `secret://` 引用**(如 `secret://kwallet/postgres/owner`),不落明文 |

## 输出

- SQL 脚本:`/etc/postgresql/daedalus/{db_name}.sql`
- reload 服务:`postgresql`
- post_check:`psql` 查询目标数据库存在

## Copilot 使用示例

```text
创建 PostgreSQL 数据库 mydb,owner 为 alice,密码从 kwallet 的 postgres/owner 取
```

或显式指定参数:

```json
{
  "db_name": "mydb",
  "owner": "alice",
  "password": "secret://kwallet/postgres/owner"
}
```

## 说明

- `password` 必须为 `secret://` 引用,蓝图插件解析后注入 SQL,**明文密码直接拒绝**。
- 模板含 `{{/* INSERTION_POINT */}}` 插入点,可追加扩展 / schema / 初始化表语句。
