#!/bin/sh
# pre_check.sh — PostgreSQL 数据库蓝图应用前验证
# 应用前检查:目标数据库是否已存在(已存在则拒绝重复创建,避免幂等歧义)。
# 参数:$1 = 数据库名(由蓝图插件从 params.db_name 注入)
# 仅使用白名单命令 psql(严格子集,与 policy.toml [blueprints].post_check_commands 一致)。
set -eu

DB_NAME="${1:?缺少参数:数据库名}"

# 查询目标数据库是否已存在
EXISTS=$(psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null)
if [ "$EXISTS" = "1" ]; then
    echo "数据库 ${DB_NAME} 已存在,拒绝重复创建" >&2
    exit 1
fi

exit 0
