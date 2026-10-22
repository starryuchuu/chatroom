# 界面截图 / Interface screenshots

这些图片是已发布 v1.3.0 客户端的真实窗口截图，展示单密码登录、旧账号迁移与旧密钥解锁入口、双栏会话布局、可收起的在线用户面板及端到端加密消息。具体操作见[单密码指南](../SINGLE_PASSWORD.md)。

These real window captures show the released v1.3.0 client: single-password login, explicit legacy-account migration and legacy-key unlock entries, two-column conversations, a collapsible online-users panel, and end-to-end encrypted messages. See the [single-password guide](../SINGLE_PASSWORD.md).

- 采集日期 / Capture date: 2026-10-22
- 客户端 / Client: v1.3.0
- 源码 / Source: [38699452cda8d5cbdd8d50d1efdb762b18de874d](https://github.com/starryuchuu/chatroom/commit/38699452cda8d5cbdd8d50d1efdb762b18de874d), the released v1.3.0 source
- 环境 / Environment: Linux, Python 3.13.5, Tk 8.6.16, 1120 × 760 client window
- [登录 / Login](login.png): single-password login and server profiles, with “迁移旧账号…” (migrate legacy account), “解锁旧密钥…” (unlock legacy keys), and key recovery entries
- [主界面 / Main](main.png): friends, groups, unread previews, notification controls and encryption status
- [聊天 / Chat](chat.png): messages delivered using real end-to-end encryption, with the key management entry visible

采集时使用临时本地 Python 服务端、全新的独立配置和演示密钥。`demo_alice`、`demo_bob`、`demo_carol`、群组和消息均为虚构数据；地址为本机回环地址。截图仅包含应用窗口，不含桌面、个人账号、私人聊天、密码、私钥、个人姓名、个人邮箱或文件路径。PNG 不附带文本或拍摄元数据。

Capture uses a temporary local Python server, fresh isolated settings and newly generated demo keys. `demo_alice`, `demo_bob`, `demo_carol`, the group and all messages are synthetic. Only the application window is captured, using a loopback address; no desktop, personal accounts, private conversations, passwords, private keys, personal names, email addresses or file paths are shown. PNG files carry no text or capture metadata.

重新采集时，应从已标明版本的源码启动客户端，使用新的临时演示账号和配置，分别拍摄空白登录页、收到演示消息后的主界面及真实加密消息往返后的聊天页。保留实际控件与状态，不将联系人首次信任标记为已核对；逐张检查隐私和文字可读性，并同步更新中英文 README 与此处的采集日期、环境和源码版本。

To refresh these images, run the documented source revision with fresh temporary demo accounts and settings. Capture the empty login page, the main view after receiving demo messages, and a conversation after a real encrypted exchange. Preserve the actual controls and status, including unverified contact trust. Review privacy and readability, then update both READMEs and the date, environment and source revision here.
