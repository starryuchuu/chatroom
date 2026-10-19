# v1.0.13 — 历史分页恢复与客户端代码整理

- 修复历史页部分送达后重试跳过消息的问题：分页游标只在对应会话完整返回 `history_end` 后推进，失败后从原游标重试，已收到的消息按 ID 去重。
- 修复登录历史快照或其他会话的历史完成事件误清除当前分页请求的问题，避免重复请求和加载按钮提前恢复。
- 修复断线后的历史同步状态残留，登录和断线统一重置历史状态、分页游标及待处理请求。
- Python 服务端的会话历史加载失败改为可重试的 `history_error`，保留当前连接；首次登录快照失败仍提示重新登录。
- 修复关闭窗口时后台线程和认证回调未清理的问题：先中断连接、等待工作线程退出并清理回调，再由主线程销毁 Tk；慢连接退出使用定时轮询，保持界面响应。
- 将客户端历史状态、分页、消息排序及群历史清理提取为 `client_history.py`，删除 Python 登录中的重复条件和不可达旧协议分支。
- 补充部分送达、失败重试、快照交错、断线重置、入群缓存及发送排队失败测试；新增 `CONTRIBUTING.md`，整理模块职责、验证命令与发布流程。
- 更新源码附件和 SHA-256 清单，确保新增模块随源码和可执行程序一起发布。

网络协议 v2、存储格式 v1 保持兼容，无需新增数据库迁移。已有 v1.0.10 至 v1.0.12 客户端仍可连接；历史分页恢复修复需要更新客户端，Python 服务端的失败重试响应也需更新服务端。Go 服务端行为不变，统一版本号并重新构建。

升级服务端前停止旧进程，备份数据库、`chat.db.key` 和 RSA 私钥。

## 验证

- 91 项 Python 回归、真实 Tk 窗口及 Go 服务端互操作测试通过。
- Go 静态检查、回归与数据竞争检测通过。发布流水线另行执行 Windows / Linux 测试后构建平台程序。

## 下载与运行

- Python：`client-windows.exe`、`server-windows.exe`、`client-linux`、`server-linux`。
- Go：`go-server-{windows,linux,darwin}-{amd64,arm64}`，Windows 文件带 `.exe`。
- 完整源码：`chatroom-v1.0.13-source.zip`；同时提供 Python 源文件、`requirements.txt` 和 `SHA256SUMS`。
- 源码运行需保留 `client_history.py`、`transport.py`、`history_store.py`、`pending_store.py`、`storage.py` 与入口脚本；打包程序已包含所需模块。
- Python 服务端默认端口为 `12345`，Go 服务端为 `12346`。Linux / macOS 二进制下载后执行 `chmod +x`；Python 客户端需要图形桌面。
