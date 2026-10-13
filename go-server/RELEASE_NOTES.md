# 未发布 — 协议 v2 与可靠历史同步

完整报文认证及防重放、登录限流、群历史权限同步、入群补发、历史分页与请求持久化已实现。需要配套新版 Python 客户端；详细行为及升级说明见 [协议说明](PROTOCOL_COMPATIBILITY.md) 和根目录发布说明。

---

# v1.0.9 — 与 Python 修复版统一发布

Go 服务端更新版本号并按统一发布流程重新构建，业务逻辑沿用 v1.0.8。本次七项修复针对 Python 客户端与 Python 服务端，详见仓库根目录 RELEASE_NOTES.md。

兼容 v1.0.9 Python 客户端，默认端口 `12346`，无需迁移数据库。提供 Windows、Linux、macOS 的 amd64 / arm64 二进制。

