# Desktop Protocol v1

此协议定义 Electron 与可替换核心（当前 Python、未来 Rust）的边界。它独立于现有远程聊天协议 transport v2、OPAQUE 与 E2EE。

## 传输

核心从 stdin 接收、向 stdout 输出 UTF-8 JSONL，每行一个 JSON-RPC 2.0 对象；单行上限 32 MiB，命令队列上限 128。stdout 仅用于协议。诊断写 stderr，不记录完整请求、密码或正文；Electron 不将核心 stderr 复制到应用日志。

启动后发送 `initialize`，参数 `{protocolVersion:1}`，返回版本、`implementation` 和完整 `state`。版本不符则拒绝。关闭发送 `shutdown`；stdin EOF 同样触发清理。桌面等待退出，4 秒后终止无响应核心；崩溃显示失败页，不自动重新认证或重发正文。

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1}}
```

响应携带原 `id`，包含 `result` 或 `error:{code,message}`。无效报文为 `-32600`，业务 / 参数错误为 `-32000`，内部错误为 `-32603`。错误不回显请求。核心通知无 `id`；当前核心不接受批量请求或无 ID 命令。

## 状态和范围

`state.changed` 推送完整投影，字段见 [`protocol.ts`](../desktop/src/protocol.ts) 的 `State`：设置、账号、好友与群、当前会话已加载消息、内存待确认发送、申请、公开身份指纹。不得包含密码、私钥、会话密钥、OPAQUE 导出密钥或本机文件路径。消息编号用十进制字符串，避免 JavaScript 丢失 64 位整数精度；无编号消息使用进程内 `local:` 标识。

会话键为 `{kind:"private"|"group",target:string}`。除 `initialize`、`shutdown` 外，请求必须携带最新 `state.session`。新账号会话或退回登录页更换令牌；旧令牌拒绝。发送、历史和草稿还校验当前会话键。核心继续校验网络 socket、认证代次和群成员代次。

UI 编辑文本只在内存。`draft.set` 同步核心；`conversation.select` 必须同时传旧会话最新 `draft`。核心通知 `draft.changed {session,key,text,previous}`，界面仅在当前文本仍等于 `previous` 时接受确认清空，防止迟到回执抹掉新编辑。

v2.0.4 新增 `state.outgoing`：当前会话的本机发送气泡，与 `state.messages` 的已验证历史分开。消息可附带 `sendStatus:sending|saved|uncertain|checking|retry|failed`；本机气泡使用 `outgoing:<记录ID>` 标识及 `protection:local`，附带 `sendId,canRecover,sendError,serverId`。本机时间和未知的服务器编号须明确标注，不将原文占位记录声称为已经过身份及完整性验证。`messages` 中带正整数编号的本人消息附带 `sendStatus:saved`。

界面只在最新历史尾部合并 `messages` 与 `outgoing`。服务器保存确认与原消息到达之间保留占位；已有对应服务器编号时不再显示占位。已验证本人消息与原待发送 E2EE 封装完全一致时，可以解决丢失的 ACK；不同聊天、验证失败、仅正文相同或旧账号不能关联。`send.recover` 沿用原核对与显式幂等重试，不新增任意正文重发 API。近期结果记录与待发送共同受 8 MiB 内存预算约束，退出后清除。

## 方法

表内省略共同的 `session`。核心验证字符串、布尔、集合及权限，不暴露任意网络发送、脚本或 shell 执行。

| 方法 | 参数 / 行为 |
| --- | --- |
| `initialize` / `shutdown` | `protocolVersion` / 无；协商版本 / 清理退出 |
| `auth.login` | `username,password,register?`；异步认证 |
| `auth.cancel` / `session.disconnect` | 无；取消认证或退出当前会话 |
| `auth.migrate` | `username,password,oldPassword,legacyPassphrase` |
| `auth.unlockLegacy` | `username,passphrase` |
| `profile.select` / `profile.delete` | `name`；连接 / 认证 / 重连时禁止 |
| `profile.save` | `name,host,port,fingerprint,replaceName?`；保存并选用 |
| `settings.theme` | `theme:light|dark` |
| `settings.notifications` | `enabled,doNotDisturb` 两个布尔值；可选 `preview:generic\|sender\|message`，省略时保留当前档位 |
| `window.activity` | `focused,atBottom`；已读和提醒判断 |
| `conversation.select` / `conversation.clear` | `key,draft` / `draft` |
| `draft.set` / `message.send` | `key,text` |
| `history.older` / `history.latest` | `key` |
| `sync.retry` / `friend.add` | 无 / `username` |
| `request.reply` | `id,accepted`；校验原 socket |
| `group.create` | `name,members`；以用户名识别成员 |
| `group.info` | `gid` |
| `group.invite` / `group.kick` / `group.transfer` | `gid,username`；后两者校验群主权限 |
| `group.rename` | `gid,name`；校验群主权限 |
| `group.leave` / `group.disband` | `gid`；解散校验群主权限 |
| `keys.reviewGroup` | `key` |
| `keys.verify` / `keys.acceptChange` | `username,fingerprint`；重新比较显示过的指纹 |
| `keys.export` / `keys.import` | `path,password` / `path,password,username` |
| `password.change` | `currentPassword,newPassword` |
| `send.recover` / `send.dismiss` | `id`；逐条核对 / 移除属于当前账号的内存记录 |
| `prompt.reply` | `id,accepted` |

渲染进程不能提供文件路径。Electron 主进程处理 `keys.import/export` 时先打开原生文件选择器，覆盖路径字段后才发送核心请求；取消选择不执行操作。

## 核验与通知

核心 `prompt` 包含 `id,title,text`；群核验附加 `gid,recipients:[{username,fingerprint,change}],removed`。默认拒绝，用户必须勾选已核对并明确确认。回复 ID、会话和布尔值必须匹配。

等待确认期间不重入网络事件，也不允许其他变更，仅接受 `prompt.reply`、`session.disconnect`、`shutdown`。120 秒超时、EOF、退出或账号变化均拒绝；结束通知 `prompt.closed`。随后既有控制器仍核验账号、socket、输入与群上下文。

其他通知：`notice {title,text}`、`auth.registered {username}`、`session.reset {session}`、`group.opened {gid}`、`draft.changed`、`conversation.latest {key}`、`conversation.uncached {key}`、`bell {}`。

v2.0.3 的 `state.notifications` 包含 `enabled,do_not_disturb,preview`。旧配置默认 `preview:sender`，不展示正文；`generic` 只提示有新消息，`message` 允许最多 140 个字符的正文摘要。核心在同一 owner 线程捕获策略、会话和聊天键，限速一秒，先刷新快照，再发送 `desktop.notification {title,body,session,key,preview}`。正文验证失败时只显示失败提示；通知不触发正文落盘。

Electron 收到后再次比较当前会话、通知档位、勿扰及聊天存在性；账号切换、静音、会话删除或档位改变时关闭仍受管理的通知。原生点击只向渲染进程发送 `notification.open {session,key}`，渲染进程再次校验并以 `conversation.select {session,key,draft}` 跳转，保留当前草稿。此事件来自 Electron，不是新增核心 RPC 方法。系统通知历史及锁屏显示由系统控制。

## 界面隔离

Electron 启用 contextIsolation、渲染沙箱和 webSecurity，禁用 Node 集成、外部导航、新窗口、webview 和浏览器权限。preload 只暴露方法白名单、订阅和显式剪贴板写入；IPC 校验发送窗口与主 frame。正文以 React 普通文本渲染，不执行 HTML。密码、草稿和正文不写 localStorage / IndexedDB。
