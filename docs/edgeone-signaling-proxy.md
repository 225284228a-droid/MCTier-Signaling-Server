# EdgeOne + 1Panel/OpenResty 信令注册失败排查

## 已确认的故障模式

链路为玩家 -> EdgeOne -> OpenResty -> Docker 信令容器。若 `TRUSTED_PROXIES` 为空，服务端忽略转发头，所有经同一 Docker 网关进入的玩家共享 `MAX_CONNECTIONS_PER_SOURCE`（默认 128）。满额时返回 HTTP 429，响应体为 `source connection capacity reached`。浏览器 WebSocket 接口不提供该 HTTP 状态和响应体，因此旧客户端只显示“无法完成信令服务器注册”。重启客户端不能修正服务端计数方式。

仅把 Docker 网关加入可信代理也不一定足够：未配置真实 IP 恢复的 OpenResty 会把 EdgeOne 节点追加到 `X-Forwarded-For` 末尾，服务端仍可能按 CDN 节点合并玩家。

## 1. 在 OpenResty 恢复经过验证的真实来源

从 EdgeOne 控制台获取当前站点完整的回源 IP 网段（IPv4 和 IPv6），并在网段变更时及时同步。不要用客户端请求头、任意内网网段或 `0.0.0.0/0` 代替官方名单。

在 1Panel 站点配置的 `server { ... }` 中，为每个官方回源 CIDR 添加一条 `set_real_ip_from CIDR;`。其中 `CIDR` 必须替换为实际网段，不能直接粘贴占位文字。然后添加：

```nginx
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

EdgeOne 必须向源站发送包含玩家真实地址的标准 `X-Forwarded-For`。仅有来自上述可信网段的连接才会启用来源恢复，直接访问源站的请求头不受信任。如果 EdgeOne 与 OpenResty 之间还有其他代理，先核对实际 TCP 来源和完整信任链。

找到真正代理 `/signaling` 的 `location`（1Panel 常放在 `proxy/*.conf` 中），将已有的同名指令替换为：

```nginx
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Real-IP $remote_addr;
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;
```

保留原有 `proxy_pass`、Host、证书和站点的其他业务配置。不要重复添加同名转发头；不要继续使用 `$proxy_add_x_forwarded_for`，否则仍会把原始 CDN 链一起传入信令服务器。此处 `$remote_addr` 是 Real IP 模块校验后的玩家地址。

Nginx 的 `proxy_set_header` 只有在下层完全未定义时才继承；仅修改 `server` 层，可能被 `proxy/*.conf` 内的 `location` 配置覆盖。因此需检查真正生效的 location。通过 1Panel 的配置检查后重载 OpenResty；检查失败时恢复原配置，不要强行重启。

## 2. 配置信令容器的可信直接上游

查询服务端日志确认容器实际看到的代理 IP：

```bash
docker logs --tail=5000 mctier-signaling 2>&1 | grep 'WebSocket 连接已建立' | tail -10
```

只有日志确认直接上游为 `172.20.0.1` 时，在 Compose 同目录的 `.env` 中添加或修改：

```dotenv
TRUSTED_PROXIES=172.20.0.1
```

保留 `.env` 中其他设置以及连接保护额度。真实 IP 已由 OpenResty 校验并压缩成单个来源，因此服务端只需信任实际直接上游，不需要再列 EdgeOne 全部网段。

确保 8445 只允许这条受控代理链访问。宿主机反代可绑定回环端口；OpenResty 位于另一容器时，应使用受限私有网络和对应防火墙规则，不要直接把上游地址改成该容器自己的 `127.0.0.1`。Docker 端口发布可能绕过普通 UFW 规则，需核对实际安全组与 Docker 转发规则。

加载新的环境变量会重建容器，现有信令连接会短暂断开，请选择合适的维护时间：

```bash
cd /mnt/dataDisk/WebBackend/MCTierServer
docker compose up -d --force-recreate mctier-signaling
docker exec mctier-signaling printenv TRUSTED_PROXIES
```

这是配置修正，不需要重新编译。若同时上传了新的服务端源码以启用详细日志，则将上面的启动命令替换为：

```bash
docker compose up -d --build --force-recreate mctier-signaling
```

## 3. 验证

更新后的服务端会在成功连接日志中显示 `quota_source`。让不同公网出口的设备分别连接：该字段应是各自的公网出口地址（IPv6 按 /64 归并），而不是统一的 Docker 网关或 EdgeOne 节点。同一家庭或同一运营商共享出口仍可能共享名额，属于按来源配额的正常行为。

```bash
docker logs --since=5m mctier-signaling 2>&1 | grep -E 'WebSocket 连接已建立|拒绝 WebSocket 握手'
```

若仍出现 `source connection capacity reached`，检查拒绝日志中的 `quota_source`。若是 `connection capacity reached`，则为全局额度已满，需要结合资源和实际在线连接规模调整全局容量。这是不同的问题，增加客户端重试次数无法代替服务端配置修正。
