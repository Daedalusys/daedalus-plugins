#!/bin/sh
# pre_check.sh — PostgreSQL 用户与权限蓝图应用前验证
# 应用前验证:目标数据库存在(GRANT 的目标库必须已存在)。
# 参数:$1 = 数据库名(由蓝图插件从 params.db 注入)
# 仅使用白名单命令 psql(严格子集,与 policy.toml [blueprints].post_check_commands 一致)。
set -eu

DB_NAME="${1:?缺少参数:数据库名}"

# 查询目标数据库是否已存在
EXISTS=$(psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null)
if [ "$EXISTS" != "1" ]; then
    echo "数据库 ${DB_NAME} 不存在,无法授予权限" >&2
    exit 1
fi

exit 0
