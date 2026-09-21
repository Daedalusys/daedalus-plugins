# post_check.sh — PostgreSQL 用户蓝图应用后验证(命令序列,argv 直发)
# 每行一条白名单命令;{user} 由蓝图插件从 params 注入。
psql -c "SELECT 1 FROM pg_roles WHERE rolname='{user}'"
