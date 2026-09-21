# Nginx 反向代理蓝图 (nginx-reverse-proxy)

添加一个 Nginx 反向代理上游(`upstream` + `location` 块),输出到
`/etc/nginx/conf.d/{name}-proxy.conf`,并 reload `nginx` 服务。

## 用途

- 为 `myapp` 添加一个反代,将请求转发到 `http://127.0.0.1:3000`。
- 通过 `path_prefix` / `strip_prefix` 控制路径前缀的保留或剥离。

## 输入参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `name` | string | ✔ | — | 反代标识名,如 `myapp` |
| `upstream_url` | string | ✔ | — | 后端上游地址(uri),如 `http://127.0.0.1:3000` |
| `path_prefix` | string | ✘ | — | location 路径前缀,如 `/api`;省略匹配 `/` |
| `strip_prefix` | bool | ✘ | `false` | 转发前是否剥离前缀(`rewrite`) |

## 输出

- 配置文件:`/etc/nginx/conf.d/{name}-proxy.conf`
- reload 服务:`nginx`
- post_check:`nginx -t` + `systemctl is-active nginx`

## Copilot 使用示例

```text
给 myapp 添加一个 nginx 反向代理,上游 http://127.0.0.1:3000,路径前缀 /api,并剥离前缀
```

或显式指定参数:

```json
{
  "name": "myapp",
  "upstream_url": "http://127.0.0.1:3000",
  "path_prefix": "/api",
  "strip_prefix": true
}
```

## 说明

- 模板含 `{{/* INSERTION_POINT */}}` 插入点,可追加代理级指令(超时、body 大小等)。
- `strip_prefix=true` 时模板生成 `rewrite` 规则剥离前缀后再 `proxy_pass`。
