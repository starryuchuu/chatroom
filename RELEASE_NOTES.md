# v1.0.12 — 并发一致性与客户端草稿修复

- 修复 Go 建群与登录群列表同步并发时的重复读锁死锁，保留群操作和通知的提交顺序。
- 修复 Python / Go 登录好友快照与接受好友申请交错时，新好友被旧列表覆盖或更新遗漏的问题。
- Go 创建群与修改群名统一限制为 1 至 128 个 Unicode 字符，拒绝纯空白名称；对旧长群名的改名通知安全截断，避免数据库已更新却无法发送结果。
- Python 公钥文件缺失、损坏或不匹配时，从现有有效私钥恢复公钥，保留服务器身份指纹；私钥损坏或丢失而身份文件尚在时停止启动，避免静默覆盖原身份。
- 客户端按实际连接的服务器地址、端口和账号分别保留进程内未发送草稿；切换账号或端口不会覆盖其他草稿，重连后只恢复输入，不自动发送。
- 增加并发时序、群名边界、公钥恢复与多账号草稿的回归测试。

网络协议 v2 和存储格式 v1 保持兼容，无需新增数据库迁移。升级前停止旧服务端，备份数据库、`chat.db.key` 和 RSA 私钥。为获得草稿修复，请同时更新客户端；已有 v1.0.10 / v1.0.11 客户端仍可连接新版服务端。

验证包含 Python 回归、真实 Tk 窗口、Python / Go 互操作，以及 Go 静态检查和数据竞争检测。发布流程在 Windows / Linux 测试通过后构建并上传平台程序。

## 下载与运行

- Python：`client-windows.exe`、`server-windows.exe`、`client-linux`、`server-linux`。
- Go：`go-server-{windows,linux,darwin}-{amd64,arm64}`，Windows 文件带 `.exe`。
- 完整源码：`chatroom-v1.0.12-source.zip`；同时提供 Python 源文件、`requirements.txt` 和 `SHA256SUMS`。
- Python 源码运行需保留 `transport.py`、`history_store.py`、`pending_store.py`、`storage.py` 与入口脚本；打包程序已包含所需模块。
- Python 服务端默认端口为 `12345`，Go 服务端为 `12346`。Linux / macOS 二进制下载后执行 `chmod +x`；Python 客户端需要图形桌面。
