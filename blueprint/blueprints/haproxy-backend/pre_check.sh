#!/bin/sh
# pre_check.sh — HAProxy backend 蓝图应用前验证
# 在写入配置前检查现有 haproxy 配置是否合法,避免新 backend 叠加后整体损坏。
# 仅使用白名单命令 haproxy(严格子集,与 policy.toml [blueprints].post_check_commands 一致)。
set -eu

# 检查现有主配置语法
haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1
exit $?
