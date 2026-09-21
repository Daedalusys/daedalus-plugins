# post_check.sh — Nginx 虚拟主机蓝图应用后验证(命令序列,argv 直发)
# 每行一条白名单命令;任一非零退出即整体失败。
nginx -t
systemctl is-active nginx
