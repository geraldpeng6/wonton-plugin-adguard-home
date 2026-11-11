# 云吞插件：AdGuard Home

开发流程见[插件开发指南](https://github.com/wontonapp/wonton-docs/blob/main/develop.md)。

把 [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) 做成云吞插件：在局域网 DNS 层拦截广告、跟踪器和恶意域名。
路由器把 DNS 指向这台主机的局域网地址后，家里的设备不需要逐台安装客户端。

本插件只开放 `53/tcp` 和 `53/udp`，不启用 DHCP、DoH、DoT、DoQ 或 DNSCrypt 对外服务。网页仍在云吞网关登录后访问，
应用不设置 `users`，不生成 admin 密码，打开即进入管理界面；3000 网页端口不发布到宿主或局域网。

应用和官方图标采用 GPL-3.0-only 及 AdGuard 商标声明；来源、处理方式和许可证全文见 [NOTICE](NOTICE)。AdGuard 名称和标志归
AdGuard Software Ltd. 所有，本插件不是 AdGuard 的官方合作、赞助或背书产品。

## 插件行为

- 默认语言留空，跟随浏览器；默认启用 AdGuard DNS filter。
- 默认上游是阿里公共 DNS 的 DoH：`https://dns.alidns.com/dns-query`，bootstrap DNS 是 `223.5.5.5` 和 `2400:3200::1`。
- `network.egress` 只给应用更新过滤清单、访问 DoH/DoT 上游；`network.lan` 只发布 DNS 端口。DHCP 不在插件范围内，用户自己在路由器上改 DNS。
- `sso: none` 表示应用不接 OIDC 或代理身份头，网关仍校验主人会话；未登录不能访问网页及管理 API。

`config/AdGuardHome.yaml` 预置上游配置以跳过首次向导；一次性 init 将它复制到可写数据目录，重装时不覆盖主人设置。

## 先跑起来

```bash
scripts/dev.sh up
scripts/dev.sh install
```

`up` 后用 `scripts/dev.sh token` 输出的主人令牌登录核心，`install` 会显示插件要的高权限并安装它。网关登录后直接进入
AdGuard Home 管理界面，不需要查找或输入第二份密码。

把路由器的 DNS 指向安装确认页显示的局域网地址。网页端口不是 LAN 端口，只有云吞网关能访问它。

## 仓库里有什么

| 路径 | 内容 |
| --- | --- |
| `docker-compose.yml` | AdGuard Home 服务、局域网 DNS 端口和 `x-wonton` 清单 |
| `config/AdGuardHome.yaml`、`config/init.sh` | 首次复制预置配置，不修改已有配置 |
| `icon.svg` | AdGuard Home 官方 favicon |
| `screenshots/` | 商店详情页截图 |
| `scripts/check.sh` | 检查插件包 |
| `scripts/dev.sh` | 起开发环境、安装、重装、卸载和查看日志 |
| `scripts/smoke-probes.sh` | `scripts/dev.sh smoke` 的网关认证、网页和宿主 DNS 探测 |
| `LICENSE`、`NOTICE` | 插件许可证、上游许可证和商标声明 |
