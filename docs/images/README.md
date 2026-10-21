# 界面截图 / Interface screenshots

这些图片是当前桌面客户端的真实窗口截图，替换了缺少服务器配置、未读摘要及端到端加密控件的旧版截图。

These are real desktop client window captures, replacing older screenshots that lacked server profiles, unread previews and end-to-end encryption controls.

- 采集日期 / Capture date: 2026-10-21
- 客户端 / Client: v1.2.0, source commit `ad259e914b5697d9e38d16a3c0a7a2b53b9b515f`
- 环境 / Environment: Linux, Tk 8.6, 1200 × 820 client window
- [登录 / Login](login.png): server profiles, local key passphrase and key restore entry
- [主界面 / Main](main.png): friends, groups, unread previews, notification controls and encryption status
- [聊天 / Chat](chat.png): messages delivered using real end-to-end encryption, with the key management entry visible

采集时使用临时本地 Python 服务端、独立配置目录和新生成的演示密钥。`demo_local`、`demo_peer`、`demo_team`、群组和消息均为虚构数据；地址为本机回环地址。截图仅包含应用窗口，不含桌面、个人账号、私人聊天、密码、私钥或文件路径。PNG 不附带文本或拍摄元数据。

Capture used a temporary local Python server, isolated client settings and newly generated demo keys. `demo_local`, `demo_peer`, `demo_team`, the group and all messages are synthetic. Only the application window is captured, using a loopback address; no desktop, personal accounts, private conversations, passwords, private keys or file paths are shown. PNG files carry no text or capture metadata.

重新采集时，应从当前源码启动客户端，使用新的临时演示账号和配置，分别拍摄空白登录页、收到演示消息后的主界面及真实加密消息往返后的聊天页。保留实际控件与状态，不将联系人首次信任标记为已核对；逐张检查隐私和文字可读性，并同步更新中英文 README 与此处的采集日期和源码版本。

To refresh these images, run the current client with fresh temporary demo accounts and settings. Capture the empty login page, the main view after receiving demo messages, and a conversation after a real encrypted exchange. Preserve the actual controls and status, including unverified contact trust. Review privacy and readability, then update both READMEs and the date and source revision here.
