#!/bin/sh
# pre_check.sh — Nginx 反向代理蓝图应用前验证
# 在写入配置前检查现有 nginx 配置是否合法,避免新反代叠加后整体损坏。
# 仅使用白名单命令 nginx(严格子集,与 policy.toml [blueprints].post_check_commands 一致)。
set -eu

# 检查 nginx 现有配置语法
nginx -t >/dev/null 2>&1
exit $?
