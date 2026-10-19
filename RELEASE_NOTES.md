# v1.0.16 — 客户端结构重构与界面生命周期整理

- 将客户端拆为应用控制器、会话模型、连接管理、协议、业务事件、历史分页、Tk 视图和群窗口组件；`client.py` 保留入口、服务器配置及兼容的协议函数导出。
- 私聊与群聊统一使用 `ChatKey` / `Conversation` / `Message`，消息、排序、去重及分页游标集中管理；移除动态群消息属性和旧历史 Mixin。所有账号状态在模型构造时初始化，界面创建不再清空业务数据。
- 网络线程只产生 `AuthResult` / `ServerEvent` 数据，不持有 Tk 回调；应用在主线程校验认证代次及 socket 身份，再更新模型和视图。
- 将长服务器事件分支改为显式处理表和独立处理函数，共用消息插入与群缓存移除逻辑。
- 视图在销毁聊天控件前取消排队的滚动回调，修复消息到达后立即断开时回调访问已销毁画布的问题。
- 保留草稿隔离、发送保存确认、历史失败重试、群权限更新、Linux / Windows 滚轮和等待线程结束后销毁 Tk 等行为，并调整现有测试以直接验证相应组件。
- 新增客户端源码包 `chatroom-v1.0.16-client.zip`，包含入口、完整客户端包、传输模块和依赖清单。结构和维护约定见[客户端结构说明](https://github.com/starryuchuu/chatroom/blob/v1.0.16/CLIENT_ARCHITECTURE.md)。

网络协议 v2、存储格式 v1 不变，兼容 v1.0.10 至 v1.0.15 服务端。本次服务端业务代码不变，统一版本号并重新构建，无需数据库迁移。

## 验证

- 客户端组件、真实 Tk 窗口、草稿和历史重试专项检查通过；Tk 8.6 与 Tk 9 均完成界面验证。
- Linux 上完整 122 项 Python、服务端、真实 Tk、Go 互操作及真实进程可靠性回归通过。Tk 8.6 的 16 项界面 / 草稿专项也通过，完整回归使用 Tk 9。发布流水线另在 Windows / Linux 运行回归后构建平台程序。
- 新增消息排序去重、会话命名空间、账号状态清理、旧认证结果和旧发送隔离、编辑中确认回执及排队滚动回调等检查。

## 下载与运行

- Python 程序：`client-windows.exe`、`server-windows.exe`、`client-linux`、`server-linux`。
- Go：`go-server-{windows,linux,darwin}-{amd64,arm64}`，Windows 文件带 `.exe`。
- 完整源码：`chatroom-v1.0.16-source.zip`。仅运行客户端可下载 `chatroom-v1.0.16-client.zip`，安装依赖后执行 `python client.py`。
- 源码客户端需要 `client.py`、完整 `chatroom_client/` 和 `transport.py` 同处一目录；配置仍在 `client.py` 顶部。打包程序已包含全部组件。
- 提供 `SHA256SUMS`；Python 服务端默认端口 `12345`，Go 服务端默认 `12346`。Linux / macOS 二进制下载后执行 `chmod +x`；客户端需要图形桌面。
