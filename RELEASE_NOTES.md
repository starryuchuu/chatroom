# v1.0.8 — Python 客户端、Python 服务端与 Go 服务端

本版本一起发布三个程序。Python 客户端可以连接配套的 Python 或 Go 服务端；Go 服务端现已适配 v1.0.7 起新增的消息保存确认、消息 ID 和历史同步协议。

## 修复与协议适配

- 保留 v1.0.7 Python 的全部 12 项可靠性与界面修复：数据库提交后确认、后台网络操作、输入保留到确认、历史去重排序、非模态通知、群窗口同步和滚轮绑定修复。
- Go 私聊与群聊返回关联原 `request_id` 的成功或失败结果；保存成功后才确认并转发，确认与实时消息携带同一个数据库 `message_id`。
- Go 历史同步发送 `history_begin` / `history_end`，全部会话共享 ID 边界，按 ID 排序；兼容旧数据库中的 NULL 列。
- Go 登录后使用每连接发送队列、5 秒写入超时和有界历史回压，群管理操作不等待网络写入。
- Go 支持拒绝邀请，删除对应待处理邀请；保留 24 小时有效期。解散、转让、改名仅向操作者返回一次操作结果，改名结果含旧名称与新名称。
- 发布流程统一版本号并从同一提交构建全部程序，验证预期文件存在后发布，同时提供 SHA-256 校验文件。

## 验证

- Go 单元测试、`go vet` 和数据竞争检测通过。
- 34 项 Python 回归测试及 5 项真实 Python/Go 互操作测试，包含真实 Tk 客户端登录、发送确认及确认后清空输入。
- 发布前在 Windows / Linux 运行完整测试；Linux 的 Tk 测试使用 Xvfb，Go 测试启用 `-race`。

## 下载与运行

- Windows Python 客户端：`client-windows.exe`；Python 服务端：`server-windows.exe`。
- Linux Python 客户端：`client-linux`；Python 服务端：`server-linux`。下载后执行 `chmod +x`，客户端需要图形桌面。
- Go 服务端：`go-server-{windows,linux,darwin}-{amd64,arm64}`，Windows 文件带 `.exe`。Linux / macOS 下载后执行 `chmod +x`。
- 完整源码：`chatroom-v1.0.8-source.zip`；同时提供 `client.py`、`server.py` 和 `requirements.txt`。
- `SHA256SUMS` 包含全部十个二进制、源码压缩包及单独提供的源码文件的 SHA-256 校验值。

Python 服务端默认端口 `12345`，Go 服务端默认端口 `12346`。在客户端登录界面选择相应端口即可；服务端实现二选一即可使用。数据库无需迁移。旧 Go v1.0.6 不支持新消息保存确认，应升级到 v1.0.8。

保存确认代表数据库已提交，不代表接收者已读。确认超时会保留输入，不自动重发；重新登录查看历史后再决定是否重试。申请与邀请仍保存在内存中，服务器重启会丢失；历史仍全量加载。
