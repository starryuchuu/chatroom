# 协议 v2：完整报文认证与分页

Python 客户端、Python 服务端与 Go 服务端需要一起升级。默认端口仍为 `12345` / `12346`。

## 握手和报文

1. 服务端发送长度头加 JSON 的 `public_key`，携带整数 `protocol: 2`。客户端校验 RSA 公钥指纹；远程连接必须配置可信指纹。
2. 客户端发送 `session_key`，携带 `protocol: 2` 和 RSA-OAEP 加密的 AES 会话密钥。旧协议不降级放行。
3. 后续每个包：4 字节网络序长度，8 字节网络序序号，UTF-8 JSON，32 字节 HMAC-SHA256。长度包括序号、JSON 和标签，最大 1 MiB。

认证覆盖序号及全部 JSON 字节，修改 `to`、`gid`、命令类型或其他字段都会被拒绝。两个方向序号独立从 0 递增，重复或乱序的报文被拒绝。方向密钥分别为 `HMAC-SHA256(session_key, "chatroom/frame/v2/client")` 和 `HMAC-SHA256(session_key, "chatroom/frame/v2/server")`。序号在实际发送顺序中分配，避免并发通知乱序；Python 和 Go 测试使用相同的固定向量。

登录继续使用 `encrypted_login`，注册使用 `encrypted_register`。不接受明文 `login`。v1.2.0 的聊天正文使用下述端到端封装；凭据仍通过传输会话的 AES-GCM 加密，路由元数据可见。旧账号的兼容消息由服务端解密后按存储 v1 保存，界面明确标记为非端到端加密。端到端协议不提供长期接收私钥泄露后的前向保密。

## 历史分页

登录最多同步最近 100 条有权读取的消息。请求更早记录：

```json
{"type":"history_request","chat_type":"private","target":"bob","before_id":123}
```

群历史使用 `chat_type: "group"` 和群 UUID 作为 `target`。游标为排他的消息 ID。回复为 `history_begin`、最多 100 条按 ID 升序排列的聊天消息、`history_end`；结束事件包含 `boundary`、`history_kind`、`history_target`、`before_id` 和 `has_more`。非法请求返回 `history_error`。每页校验好友或成员资格，群消息排队前在群操作锁内再次校验。

实时和历史共用 SQLite `message_id`，客户端去重、排序。退出或被踢后删除该群缓存及对应去重 ID，允许重新入群后正确恢复历史。Go 入群成功后也立即补发该群最近历史。

## 持久化与兼容性

### v1.2.0 端到端封装

握手增加 `e2ee_v1`，登录成功返回 `e2ee_identity`（未登记时为 `null`）。`e2ee_identity_publish` 携带身份包和绑定账号的持有证明，首次登记后不可替换；`e2ee_keys_request` 仅允许查询已授权私聊或当前所在群的接收人密钥。每次响应均回传 `request_id`。

`private_chat` / `group_chat` 的新消息使用 `e2ee` 对象代替 `content`。服务端核对签名、已登记身份、当前完整接收人集合和帧预算，再保存原封装；实时、历史及同步回传相同对象，不解密或重新加密正文。数据库新增 `messages.e2ee` 标志及加密保存的公钥目录；旧正文不会因内容碰巧是 JSON 而被识别为加密封装。旧消息带 `encryption: "legacy"`（接近帧上限时可省略该标签），客户端仍将缺少 `e2ee` 的历史识别为旧消息。

加密账号与其接收人的明文降级发送会被拒绝。客户端不能把服务端可伪造的 `history`、时间或编号当作旧信任仍有效的证据。封装格式、签名规范化、密钥备份、首次信任及前向保密限制见 [端到端加密说明](../END_TO_END_ENCRYPTION.md)。

### v1.1.0 增量补取

支持完整断线补取的服务端在 `public_key` 中增加 `capabilities: ["message_sync"]`。客户端只有看到此能力才发送 `sync_request`；旧客户端忽略新增字段，帧格式仍为 v2。实时聊天帧显式携带 `history: false`，历史聊天帧携带 `history: true`，增量聊天帧通常还带 `sync: true`；客户端优先识别显式实时标记，避免登录/补取期间交错到达的新消息被误标已读。旧版本近长度上限的历史消息可省略可选标记，客户端也使用批次状态识别历史。

```json
{"type":"sync_request","after_id":123,"boundary":456,"request_id":"unique-page-id"}
```

`after_id` 为排他下界，`boundary` 为包含的上界；省略 `boundary` 时使用当前最大消息 ID。两者为 0 至 9007199254740991 的整数，且 `after_id <= boundary <= 当前最大 ID`。`request_id` 为 1–128 个 Unicode 字符。

回复依次为 `sync_begin`、最多 100 条当前有权读取的聊天消息、`sync_end`，按 ID 升序排列。开始与结束事件均回显 `request_id`、`after_id`、`boundary`；结束事件另有 `has_more`、`next_after_id`。有下一页时游标为本页最后一条 ID，否则为 `boundary`。客户端后续请求保持同一上界。群消息排队前再次校验成员资格。失败返回关联 `request_id` 的 `sync_error`，不能据此推进完成游标。

新客户端在第一次账号登录时使用最近历史建立基线。后续登录和异常重连按该账号已持久化的完成位置补取全部新消息，只有所有页成功到达才保存新位置。旧服务端不支持该请求时仅提供最近历史，客户端保留旧位置，升级服务端后可继续补齐。

启动时自动增加 `pending_friend_requests`、`pending_group_invites` 及消息索引。申请与邀请有效期 24 小时，重启后恢复；接受好友或入群在数据库事务中消费申请，拒绝时先删除持久化记录再通知成功。原有账号和聊天记录保留。

保存确认仍携带请求 ID 和提交后的消息 ID。未收到确认的发送结果仍属于未知状态，客户端保留输入，避免自动重发。

## 存储格式 v1

网络协议与存储格式分别版本化。此修改仍使用协议 v2，兼容 v1.0.10 客户端。Python 与 Go 可以顺序使用同一迁移后的数据库和 `chat.db.key`，不得同时运行或降级使用旧服务端。详情见 [存储说明](../STORAGE_ENCRYPTION.md)。
