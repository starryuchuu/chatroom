# 界面截图 / Interface screenshots

**历史截图：以下为 v1.2.1，包含旧版独立本机口令输入，不作为 v1.3.0 单密码界面截图。新版操作见[单密码指南](../SINGLE_PASSWORD.md)。**

**Historical captures: these v1.2.1 images include the former separate local passphrase and do not illustrate the v1.3.0 single-password interface. See the [single-password guide](../SINGLE_PASSWORD.md).**

这些图片是 v1.2.1 雾白与石墨桌面界面的真实窗口截图，展示统一的登录表单、双栏会话布局、可收起的在线用户面板及端到端加密消息。

These real window captures show the v1.2.1 fog-white and graphite desktop interface: a consistent login form, two-column conversations, a collapsible online-users panel and end-to-end encrypted messages.

- 采集日期 / Capture date: 2026-10-21
- 客户端 / Client: v1.2.1, UI source included in the `v1.2.1` release
- 环境 / Environment: Linux, Python 3.13, Tk 8.6, 1120 × 760 client window
- [登录 / Login](login.png): server profiles, local key passphrase and key restore entry
- [主界面 / Main](main.png): friends, groups, unread previews, notification controls and encryption status
- [聊天 / Chat](chat.png): messages delivered using real end-to-end encryption, with the key management entry visible

采集时使用临时本地 Python 服务端、独立配置目录和新生成的演示密钥。`alice`、`bob`、`carol`、群组和消息均为虚构数据；地址为本机回环地址。截图仅包含应用窗口，不含桌面、个人账号、私人聊天、密码、私钥或文件路径。PNG 不附带文本或拍摄元数据。

Capture used a temporary local Python server, isolated client settings and newly generated demo keys. `alice`, `bob`, `carol`, the group and all messages are synthetic. Only the application window is captured, using a loopback address; no desktop, personal accounts, private conversations, passwords, private keys or file paths are shown. PNG files carry no text or capture metadata.

重新采集时，应从当前源码启动客户端，使用新的临时演示账号和配置，分别拍摄空白登录页、收到演示消息后的主界面及真实加密消息往返后的聊天页。保留实际控件与状态，不将联系人首次信任标记为已核对；逐张检查隐私和文字可读性，并同步更新中英文 README 与此处的采集日期和源码版本。

To refresh these images, run the current client with fresh temporary demo accounts and settings. Capture the empty login page, the main view after receiving demo messages, and a conversation after a real encrypted exchange. Preserve the actual controls and status, including unverified contact trust. Review privacy and readability, then update both READMEs and the date and source revision here.
