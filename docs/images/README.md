# 界面截图 / Interface screenshots

## v2.0.4 Electron 桌面 / Current desktop

首页的深浅色聊天图已更新到 [v2.0.4](https://github.com/starryuchuu/chatroom/tree/v2.0.4)，展示左右对齐的气泡及本人消息的服务器保存状态。发送状态图展示已保存、保存结果待确认、核对入口与失败原因；这些状态从 v2.0.4 起提供。

The README chat previews now use [v2.0.4](https://github.com/starryuchuu/chatroom/tree/v2.0.4), showing incoming/outgoing bubbles and server persistence status. Additional status captures demonstrate saved, uncertain and failed sends with reconciliation controls and failure reasons.

- 采集日期 / Capture date: 2026-10-28（Asia/Shanghai）
- 环境 / Environment: Linux, Electron 45.0.0, 1180 × 791 content area
- [浅色聊天 / Light chat](electron-chat.png)、[深色聊天 / Dark chat](electron-chat-dark.png): 当前聊天布局及「服务器已保存」状态 / Current chat layout and saved status
- [浅色发送状态 / Light send states](message-send-status-light.png)、[深色发送状态 / Dark send states](message-send-status-dark.png): 已保存、待确认、核对入口及失败原因 / Saved, uncertain, reconciliation and failure states

以上图片由真实 Electron 渲染器从隔离临时配置采集，账号、聊天和状态是虚构展示数据，不包含系统标题栏。截图不作为真实加密、回执或收件人已读的证据；相关行为由核心测试与 Python / Go 双服务端桌面互操作测试验证。单勾仅表示服务器保存，不表示对方收到或已读。

These images were captured from the actual Electron renderer with isolated temporary configuration and synthetic accounts, messages and states. They exclude the native system title bar. They do not establish real E2EE, receipt or read behavior; core tests and desktop interoperability tests against both servers verify the relevant behavior separately. A single check indicates server persistence only.

其他 Electron 截图保留对应功能的采集记录：`electron-login-dark.png` 于 2026-10-27 使用虚构渲染数据采集；`electron-online-users.png` 使用真实本机测试服务和虚构账号 `alice`、`bob` 展示侧栏入口与在线列表；`electron-notification-settings.png` 展示 v2.0.3 起提供的通知内容设置。见[桌面指南](../DESKTOP_CLIENT.md)与 [Electron 迁移验证](../reviews/ELECTRON_MIGRATION_VALIDATION.md)。

Other Electron captures show login, online users and notification settings. The dark login capture dates from 2026-10-27 and uses synthetic rendering data; the online-user capture uses a local test server and synthetic `alice` / `bob` accounts. Notification content settings are available from v2.0.3. See the [desktop guide](../DESKTOP_CLIENT.md) and [migration validation](../reviews/ELECTRON_MIGRATION_VALIDATION.md).

## v1.3.2 历史截图 / Historical screenshots

这些图片是 v1.3.2 客户端的真实窗口截图，展示深浅色主题、单密码登录、旧账号迁移与旧密钥解锁入口、双栏会话布局、可收起的在线用户面板及端到端加密消息。认证操作见[单密码指南](../SINGLE_PASSWORD.md)。

These real window captures show the v1.3.2 client: light and dark themes, single-password login, explicit legacy-account migration and legacy-key unlock entries, two-column conversations, a collapsible online-users panel, and end-to-end encrypted messages. See the [single-password guide](../SINGLE_PASSWORD.md).

- 采集日期 / Capture date: 2026-10-23
- 客户端 / Client: v1.3.2
- 源码 / Source: [v1.3.2 tag](https://github.com/starryuchuu/chatroom/tree/v1.3.2)
- 环境 / Environment: Linux, Python 3.13.5, Tk 8.6.16, 1120 × 760 client window
- [登录 / Login](login.png): light single-password login, server profiles, theme switch, “迁移旧账号…” (migrate legacy account), “解锁旧密钥…” (unlock legacy keys), and key recovery entries
- [主界面 / Main](main.png): light friends/groups view, unread previews, notification controls and encryption status
- [浅色聊天 / Light chat](chat.png): real end-to-end encrypted messages and the key management entry
- [深色聊天 / Dark chat](chat-dark.png): the dark theme applied to the chat window, with the “浅色模式” action to switch back

## 切换主题 / Switching themes

登录页或聊天页右上角的“深色模式” / “浅色模式”按钮显示将要切换的模式。切换立即生效，保留输入、草稿、聊天连接和已打开的应用对话框。选择保存在 `client.json` 顶层 `theme` 字段，取值 `light` 或 `dark`，默认 `light`；没有自动跟随系统的选项。系统原生文件选择器和消息框由操作系统管理。

The “深色模式” / “浅色模式” button at the top right of login or chat names the mode it will activate. Switching takes effect immediately and retains input, drafts, the chat connection and open application dialogs. The choice is saved in the top-level `theme` field of `client.json`, with `light` or `dark` and a default of `light`; there is no automatic system-theme option. Native file pickers and message boxes are managed by the operating system.

v1.3.2 阅读历史时收到新消息会保留当前可见消息，聊天区的“N 条新消息 ↓”可回到底部；好友和群聊列表也保留滚动及键盘导航位置。该入口只在真实收到未跟随的新消息后显示，截图不绘制或叠加虚构控件。

In v1.3.2, arrivals retain the visible historical message while “N 条新消息 ↓” returns to the latest messages. Friend/group lists also retain their scroll and keyboard navigation positions. The indicator appears after an actual arrival while reading earlier history; captures do not draw or overlay mock controls.

## v1.3.2 演示数据与采集 / Historical demo data and capture

采集时使用临时本地 Python 服务端、全新的独立配置和演示密钥。`demo_alice`、`demo_bob`、`demo_carol`、群组和消息均为虚构数据；地址为本机回环地址。截图仅包含应用窗口，不含桌面、个人账号、私人聊天、密码、私钥、个人姓名、个人邮箱或文件路径。PNG 不附带文本或拍摄元数据。

Capture uses a temporary local Python server, fresh isolated settings and newly generated demo keys. `demo_alice`, `demo_bob`, `demo_carol`, the group and all messages are synthetic. Only the application window is captured, using a loopback address; no desktop, personal accounts, private conversations, passwords, private keys, personal names, email addresses or file paths are shown. PNG files carry no text or capture metadata.

重新采集时，应从已标明版本的源码启动客户端，使用新的临时演示账号和配置，分别拍摄空白登录页、收到演示消息后的主界面，以及真实加密消息往返后的浅色和深色聊天页。保留实际控件与状态，不将联系人首次信任标记为已核对；逐张检查隐私和文字可读性，并同步更新中英文 README 与此处的采集日期、环境和源码版本。

To refresh these images, run the documented source revision with fresh temporary demo accounts and settings. Capture the empty login page, the main view after receiving demo messages, and light/dark conversations after a real encrypted exchange. Preserve the actual controls and status, including unverified contact trust. Review privacy and readability, then update both READMEs and the date, environment and source version here.
