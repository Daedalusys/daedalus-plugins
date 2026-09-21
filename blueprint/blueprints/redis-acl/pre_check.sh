#!/bin/sh
# pre_check.sh — Redis ACL 用户蓝图应用前验证
# 应用前验证:Redis 实例可达(避免写入 ACL 文件后 reload 失败)。
# 仅使用白名单命令 redis-cli(严格子集,与 policy.toml [blueprints].post_check_commands 一致)。
set -eu

# ping 验证 Redis 连接
redis-cli ping >/dev/null 2>&1
exit $?
