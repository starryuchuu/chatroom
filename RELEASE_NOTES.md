# v1.0.11 — 服务端敏感数据加密存储

- Python / Go 服务端统一采用 AES-256-GCM 加密聊天正文、聊天时间、用户名映射、密码哈希和群信息；用户名查询、好友关系与申请使用 HMAC-SHA256 索引。
- 独立随机存储密钥默认保存为 `chat.db.key`，支持 `CHATROOM_STORAGE_KEY_FILE` 外部密钥路径；缺失、损坏或不匹配的密钥会停止启动。
- 旧数据库在监听端口前事务迁移，并清理旧空闲页和 WAL；失败回滚，中断清理可在重启后继续。
- 正文绑定消息 ID 和会话字段，拒绝篡改、跨行替换及迁移后明文回退。
- Go 密码验证读取有资源上限的 Argon2 参数，兼容当前 Python 服务端生成的账号哈希。
- 更新存储说明、备份与恢复步骤，并将 `storage.py` 加入 Release 源码附件及校验文件。

升级前先停止旧服务端并备份原数据库。客户端协议 v2 不变，v1.0.10 客户端可继续使用；升级服务端后必须单独备份对应的 `chat.db.key`。密钥丢失后无法恢复数据，请勿将迁移后的数据库交给旧服务端打开。

SQLite 结构、记录及群 ID、索引关系、请求过期时间和数量仍可见；运行中的服务端可解密数据。详细范围见 [存储说明](https://github.com/starryuchuu/chatroom/blob/v1.0.11/STORAGE_ENCRYPTION.md)。

验证：Windows / Linux 各 70 项 Python / Tk / Go 互操作测试通过，Go 静态检查、回归及 Linux 数据竞争检测通过；包含迁移回滚、密钥恢复、明文残留扫描、篡改拒绝和跨语言数据库兼容测试。

## 下载与运行

- Python：`client-windows.exe`、`server-windows.exe`、`client-linux`、`server-linux`。
- Go：`go-server-{windows,linux,darwin}-{amd64,arm64}`，Windows 文件带 `.exe`。
- 完整源码：`chatroom-v1.0.11-source.zip`；同时提供 Python 源文件、`requirements.txt` 和 `SHA256SUMS`。
- Python 源码运行需保留 `transport.py`、`history_store.py`、`pending_store.py`、`storage.py` 与入口脚本；打包程序已包含所需模块。
- Python 服务端默认端口为 `12345`，Go 服务端为 `12346`。Linux / macOS 二进制下载后执行 `chmod +x`；Python 客户端需要图形桌面。
