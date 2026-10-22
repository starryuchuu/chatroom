# v1.3.1 — 可保存的深色模式

## 桌面主题

- 登录页和聊天页右上角新增“深色模式” / “浅色模式”按钮，点击立即切换。默认保持浅色，选择会保存到本机设置，重启后自动恢复。
- 深色配色覆盖消息气泡、输入框、侧栏、菜单、服务器设置、群聊和密钥管理窗口；已打开的应用窗口同步更新。系统原生标题栏、文件选择框和消息框的外观由操作系统管理。
- 切换主题直接重涂现有控件，保留登录输入、未发送草稿、选中会话、消息和连接；保存失败时保留当前主题并提示。
- 登录页采用居中表单卡片，区分登录与账号恢复操作；聊天页整理工具栏、账号侧栏、输入区和空会话提示。会话摘要按实际字体与可用宽度显示省略号，保留未读计数和键盘导航位置；输入区提供清晰的焦点边框。
- 登录卡片在高 DPI 或高度不足时支持滚动，Tab 聚焦的输入框和操作会自动进入可见区域，普通尺寸保持居中布局。
- 中英文 README 同步更新真实界面截图，新增深色聊天预览。所有截图均使用临时本地服务和虚构演示账号。

## 设置与兼容

- 本机 `client.json` 新增 `theme` 元数据，只接受 `light` / `dark`；旧配置缺省为浅色。设置格式仍为版本 1，保存继续通过文件锁合并其他客户端的服务器、提醒和账号状态。
- 本次更新兼容 v1.3.0 Python / Go 服务端，不改变认证、端到端身份、传输协议、数据库结构和密钥格式。服务端仅同步发布版本号，无需数据库迁移；从更早版本升级仍须遵循[单密码指南](https://github.com/starryuchuu/chatroom/blob/master/docs/SINGLE_PASSWORD.md)。
- Windows / Linux 客户端、Python 服务端和 Go 多平台附件见 [v1.3.1 发布页](https://github.com/starryuchuu/chatroom/releases/tag/v1.3.1)。源码包为 `chatroom-v1.3.1-client.zip` 和 `chatroom-v1.3.1-source.zip`；下载后使用同页 `SHA256SUMS` 校验。

v1.3.0 引入的 OPAQUE 单密码登录和加密身份恢复继续使用，详细说明见[上一版本发布记录](https://github.com/starryuchuu/chatroom/releases/tag/v1.3.0)和[端到端加密与恢复指南](https://github.com/starryuchuu/chatroom/blob/master/docs/END_TO_END_ENCRYPTION.md)。
