# post_check.sh — HAProxy backend 蓝图应用后验证(命令序列,argv 直发)
# 每行一条白名单命令;任一非零退出即整体失败。
haproxy -c -f /etc/haproxy/haproxy.cfg
