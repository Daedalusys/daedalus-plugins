# post_check.sh — Redis ACL 用户蓝图应用后验证(命令序列,argv 直发)
# 每行一条白名单命令;{user} 由蓝图插件从 params 注入。
redis-cli ACL GETUSER {user}
