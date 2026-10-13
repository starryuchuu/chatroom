# 协议 v2：完整报文认证与分页

Python 客户端、Python 服务端与 Go 服务端需要一起升级。默认端口仍为 `12345` / `12346`。

## 握手和报文

1. 服务端发送长度头加 JSON 的 `public_key`，携带整数 `protocol: 2`。客户端校验 RSA 公钥指纹；远程连接必须配置可信指纹。
2. 客户端发送 `session_key`，携带 `protocol: 2` 和 RSA-OAEP 加密的 AES 会话密钥。旧协议不降级放行。
3. 后续每个包：4 字节网络序长度，8 字节网络序序号，UTF-8 JSON，32 字节 HMAC-SHA256。长度包括序号、JSON 和标签，最大 1 MiB。

认证覆盖序号及全部 JSON 字节，修改 `to`、`gid`、命令类型或其他字段都会被拒绝。两个方向序号独立从 0 递增，重复或乱序的报文被拒绝。方向密钥分别为 `HMAC-SHA256(session_key, "chatroom/frame/v2/client")` 和 `HMAC-SHA256(session_key, "chatroom/frame/v2/server")`。序号在实际发送顺序中分配，避免并发通知乱序；Python 和 Go 测试使用相同的固定向量。

登录继续使用 `encrypted_login`，注册使用 `encrypted_register`。不接受明文 `login`。聊天正文和凭据保留 AES-GCM 加密；路由元数据可见。服务端解密后按存储 v1 加密保存正文，因此本协议不是用户之间的端到端加密，也不提供前向保密。

## 历史分页

登录最多同步最近 100 条有权读取的消息。请求更早记录：

```json
{"type":"history_request","chat_type":"private","target":"bob","before_id":123}
```

群历史使用 `chat_type: "group"` 和群 UUID 作为 `target`。游标为排他的消息 ID。回复为 `history_begin`、最多 100 条按 ID 升序排列的聊天消息、`history_end`；结束事件包含 `boundary`、`history_kind`、`history_target`、`before_id` 和 `has_more`。非法请求返回 `history_error`。每页校验好友或成员资格，群消息排队前在群操作锁内再次校验。

实时和历史共用 SQLite `message_id`，客户端去重、排序。退出或被踢后删除该群缓存及对应去重 ID，允许重新入群后正确恢复历史。Go 入群成功后也立即补发该群最近历史。

## 持久化与兼容性

启动时自动增加 `pending_friend_requests`、`pending_group_invites` 及消息索引。申请与邀请有效期 24 小时，重启后恢复；接受好友或入群在数据库事务中消费申请，拒绝时先删除持久化记录再通知成功。原有账号和聊天记录保留。

保存确认仍携带请求 ID 和提交后的消息 ID。未收到确认的发送结果仍属于未知状态，客户端保留输入，避免自动重发。

## 存储格式 v1

网络协议与存储格式分别版本化。此修改仍使用协议 v2，兼容 v1.0.10 客户端。Python 与 Go 可以顺序使用同一迁移后的数据库和 `chat.db.key`，不得同时运行或降级使用旧服务端。详情见 [存储说明](../STORAGE_ENCRYPTION.md)。
