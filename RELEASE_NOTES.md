# v1.0.14 — 群信息并发顺序与 Linux 滚轮修复

- Python 服务端的群信息读取、成员权限检查及响应入队现在与踢人、解散、改名和转让群主共用群操作锁。旧群信息会先于后续变更通知入队，避免客户端在被踢出后恢复已移除的群，或用旧名称、旧群主覆盖最新状态。
- 群查询在数据库操作抛异常时也会关闭连接；错误、无权限及群不存在等响应路径都会释放群操作锁，后续群操作可继续执行。
- 客户端补齐 Linux X11 的 `<Button-4>` / `<Button-5>` 滚轮事件，保留 `<MouseWheel>`。绑定仅作用于聊天画布、会话框架和消息气泡及其文字、时间戳，不影响输入框等其他控件。
- X11 滚动方向由绑定事件确定，兼容 Tk 8.6 与 Tk 9 对按钮编号的不同处理。
- 统一聊天区域的滚轮绑定方法，会话框架创建时绑定一次，切换会话无需重复注册。
- 新增群信息与四类变更交错、权限及异常分支、数据库连接关闭和两类滚轮双向滚动的回归测试。

网络协议 v2、存储格式 v1 不变，无需数据库迁移。兼容 v1.0.10 至 v1.0.13 客户端；修复群信息顺序需升级 Python 服务端，修复 X11 滚轮需升级客户端。Go 服务端行为不变，统一版本号并重新构建。

升级服务端前停止旧进程，备份数据库、`chat.db.key` 和 RSA 私钥。

## 验证

- Linux 上 99 项 Python、真实 Tk 窗口和 Go 互操作测试通过；Tk 8.6 与 Tk 9 的界面专项测试均通过。新增并发测试已验证在 v1.0.13 上失败、修复后通过。
- Go 静态检查、回归与数据竞争检测通过。发布流水线另行运行 Windows / Linux 回归，再构建各平台程序。
- X11 专用滚轮测试在 Windows 上按平台跳过；通用 `<MouseWheel>` 测试在两个平台运行。

## 下载与运行

- Python：`client-windows.exe`、`server-windows.exe`、`client-linux`、`server-linux`。
- Go：`go-server-{windows,linux,darwin}-{amd64,arm64}`，Windows 文件带 `.exe`。
- 完整源码：`chatroom-v1.0.14-source.zip`；同时提供 Python 源文件、`requirements.txt` 和 `SHA256SUMS`。
- 源码运行需保留 `client_history.py`、`transport.py`、`history_store.py`、`pending_store.py`、`storage.py` 与入口脚本；打包程序已包含所需模块。
- Python 服务端默认端口为 `12345`，Go 服务端为 `12346`。Linux / macOS 二进制下载后执行 `chmod +x`；Python 客户端需要图形桌面。
