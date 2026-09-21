# Nginx 虚拟主机蓝图 (nginx-vhost)

添加或删除一个 Nginx 虚拟主机(vhost)配置,生成标准 `server block` 到
`/etc/nginx/conf.d/{domain}.conf`,并 reload `nginx` 服务。

## 用途

- 为 `example.com` 添加一个 vhost(静态站点或反代到后端)。
- 管理 `listen_ports`、SSL 证书挂载段。

## 输入参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `domain` | string | ✔ | — | 虚拟主机域名,如 `example.com` |
| `backend` | string | ✘ | — | 反代后端地址,如 `http://127.0.0.1:8080`;省略则生成静态站点占位 |
| `ssl` | bool | ✘ | `false` | 是否生成 SSL 监听段(443 + 证书) |
| `listen_ports` | int[] | ✘ | `[80, 443]` | 监听端口列表 |

## 输出

- 配置文件:`/etc/nginx/conf.d/{domain}.conf`
- reload 服务:`nginx`
- post_check:`nginx -t` + `systemctl is-active nginx`

## Copilot 使用示例

```text
给 example.com 添加一个 nginx vhost,反代到 http://127.0.0.1:8080,开启 SSL
```

或显式指定参数(蓝图 `blueprint_render` / `blueprint_apply`):

```json
{
  "domain": "example.com",
  "backend": "http://127.0.0.1:8080",
  "ssl": true,
  "listen_ports": [80, 443]
}
```

## 说明

- 模板含 `{{/* INSERTION_POINT */}}` 插入点,多蓝图共享数据时在此追加 vhost 级指令。
- 删除 vhost 走 `blueprint_remove`,按 output_path_template 定位配置文件并反向回滚。
