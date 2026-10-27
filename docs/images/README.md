# 界面截图 / Interface screenshots

## Electron 开发分支 / Development desktop

`electron-chat.png`、`electron-chat-dark.png`、`electron-login-dark.png` 于 2026-10-27 在真实 Electron 45.0.0 Linux 窗口中采集。账号、会话和文字是合成渲染夹具；真实加密互操作另经 Python / Go 服务端及双 Electron 窗口验证。见 [Electron 迁移验证](../reviews/ELECTRON_MIGRATION_VALIDATION.md)。

新增 `electron-online-users.png` 展示新侧栏入口与在线列表，使用真实本机测试服务和虚构账号 `alice`、`bob` 采集。

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

## 演示数据与采集 / Demo data and capture

采集时使用临时本地 Python 服务端、全新的独立配置和演示密钥。`demo_alice`、`demo_bob`、`demo_carol`、群组和消息均为虚构数据；地址为本机回环地址。截图仅包含应用窗口，不含桌面、个人账号、私人聊天、密码、私钥、个人姓名、个人邮箱或文件路径。PNG 不附带文本或拍摄元数据。

Capture uses a temporary local Python server, fresh isolated settings and newly generated demo keys. `demo_alice`, `demo_bob`, `demo_carol`, the group and all messages are synthetic. Only the application window is captured, using a loopback address; no desktop, personal accounts, private conversations, passwords, private keys, personal names, email addresses or file paths are shown. PNG files carry no text or capture metadata.

重新采集时，应从已标明版本的源码启动客户端，使用新的临时演示账号和配置，分别拍摄空白登录页、收到演示消息后的主界面，以及真实加密消息往返后的浅色和深色聊天页。保留实际控件与状态，不将联系人首次信任标记为已核对；逐张检查隐私和文字可读性，并同步更新中英文 README 与此处的采集日期、环境和源码版本。

To refresh these images, run the documented source revision with fresh temporary demo accounts and settings. Capture the empty login page, the main view after receiving demo messages, and light/dark conversations after a real encrypted exchange. Preserve the actual controls and status, including unverified contact trust. Review privacy and readability, then update both READMEs and the date, environment and source version here.
