# v1.0.15 — Go 身份恢复与真实进程可靠性验证

- 修复 Go 服务端在 RSA 私钥丢失、公钥仍存在时自动生成新身份并覆盖原公钥的问题。现在会停止启动，保留已有公钥并提示恢复原私钥；恢复后原客户端指纹继续有效。
- Go 服务端在 POSIX 系统上收紧已有私钥权限为 `0600`，新私钥从创建时即使用该权限，并以独占创建避免覆盖已存在的私钥。
- 新增两端各 7 个真实服务端进程测试，覆盖并发私聊与群聊、发送中强制终止、离线申请恢复、重连与废弃握手、SQLite 写入失败后重试、TCP 分片及非法请求与报文隔离。测试使用临时数据，纳入 Windows / Linux 发布回归。
- 分别以 8 个客户端、1,200 条消息及 32 个客户端、1,120 条消息验证两端；逐条核对实时投递、数据库记录和强制重启后的分页历史。详细方法和适用边界见[可靠性验证记录](https://github.com/starryuchuu/chatroom/blob/v1.0.15/RELIABILITY_VALIDATION.md)。

网络协议 v2、存储格式 v1 不变，无需数据库迁移。兼容 v1.0.10 至 v1.0.14 客户端。Python 客户端和服务端业务代码不变，统一版本号并重新构建。

升级服务端前停止旧进程，备份数据库、`chat.db.key` 和 RSA 私钥。若 Go 服务端已有公钥而私钥丢失，应恢复原 `private_key.pem`；删除公钥重新生成会改变服务器身份，需要重新核验客户端指纹。

## 验证

- 新增密钥恢复与权限回归用例，已确认在旧实现上失败、修复后通过。
- Linux 上完整 113 项 Python、真实 Tk 窗口、Go 互操作及真实进程可靠性测试通过；Go 静态检查、回归和数据竞争检测通过。
- 发布流水线在 Windows / Linux 运行回归，再构建 Python 双平台及 Go 六平台程序。

## 下载与运行

- Python：`client-windows.exe`、`server-windows.exe`、`client-linux`、`server-linux`。
- Go：`go-server-{windows,linux,darwin}-{amd64,arm64}`，Windows 文件带 `.exe`。
- 完整源码：`chatroom-v1.0.15-source.zip`；同时提供 Python 源文件、`requirements.txt` 和 `SHA256SUMS`。
- 源码运行需保留 `client_history.py`、`transport.py`、`history_store.py`、`pending_store.py`、`storage.py` 与入口脚本；打包程序已包含所需模块。
- Python 服务端默认端口为 `12345`，Go 服务端为 `12346`。Linux / macOS 二进制下载后执行 `chmod +x`；Python 客户端需要图形桌面。
