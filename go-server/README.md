# Go Chatroom Server

## 当前版本：v1.2.1，协议 v2

从不支持端到端加密的旧版本升级时，需要配套升级 Python 客户端和 Go 服务端。完整报文（包括路由和群管理字段）使用 HMAC-SHA256 认证及独立方向序号，拒绝篡改、反射和重放；RSA/AES-GCM 继续用于传输密钥交换与凭据加密。v1.2.1 桌面客户端沿用 v1.2.0 引入的端到端加密，Go 服务端只验证公开签名并保存、转发密文，不能解开正文。元数据仍可见，SQLite 存储层继续加密敏感字段和密文封装；旧历史明确标记为非端到端加密。旧版未认证协议和明文登录不再接受。详情见[端到端加密、备份与限制](../docs/END_TO_END_ENCRYPTION.md)。

v1.2.1 为配套桌面界面更新，服务端协议与数据库结构没有变化；v1.2.0 服务端也可继续配合新版客户端使用。

默认监听 `127.0.0.1:12346`，在新版客户端登录界面的端口框输入 `12346`。旧数据库启动时自动增加持久化申请表及消息索引，保留原有账号和消息。

好友申请与群邀请重启后恢复，24 小时后过期。登录及入群最多同步 100 条最近历史，客户端支持加载更早的消息；发送群历史时重新检查成员资格并与踢人、退出、解散共用锁。群组登录快照及大快照分包也与群操作同步。

认证失败限制为同 IP 5 次/60 秒，最多 4 个并发认证和 128 个连接，成功认证不清空失败记录。消息保存确认继续代表数据库提交，不代表对方已读。

仅在 RSA 公钥与私钥均不存在时生成新身份。公钥仍存在而私钥丢失时，启动会停止，需从备份恢复原 `private_key.pem`；恢复后客户端固定的公钥指纹保持有效。私钥在 POSIX 系统上以 `0600` 权限创建，启动时也会收紧已有私钥的权限。

## 下载与验证

详见 [发布说明](RELEASE_NOTES.md)。发布程序支持 Windows、Linux、macOS 的 amd64 与 arm64，默认监听 `127.0.0.1:12346`，必须使用同分支的协议 v2 Python 客户端。

```bash
go test ./...
go vet ./...
# Linux 上检查并发数据竞争
go test -race ./...
```

这是一个用Go语言编写的聊天室服务端，具有以下功能：

## 功能特性

- 用户注册和登录
- 私聊功能
- 好友系统（添加好友、好友列表）
- 群组聊天
- 完整的群组管理功能：
  - 创建群组
  - 邀请成员
  - 加入群组
  - 退出群组
  - 踢出成员
  - 获取群组信息
  - 解散群组
  - 转让群主
  - 重命名群组
- 消息加密（RSA + AES）
- SQLite数据库存储

## 目录结构

```
go-server/
├── chatroom-server.exe      # 编译后的可执行文件
├── go.mod                   # Go模块定义
├── go.sum                   # Go模块校验和
├── README.md                # 本说明文件
├── start.bat                # Windows启动脚本
├── cmd/
│   └── server/
│       └── main.go          # 服务端主程序入口
├── internal/
│   ├── crypto/
│   │   └── crypto.go        # 加密相关功能
│   ├── database/
│   │   ├── database.go      # 数据库初始化
│   │   ├── friend_queries.go # 好友相关数据库操作
│   │   ├── group_queries.go # 群组相关数据库操作
│   │   ├── message_queries.go # 消息相关数据库操作
│   │   ├── password_test.go # Argon2 密码哈希单元测试
│   │   └── user_queries.go  # 用户相关数据库操作
│   ├── handlers/
│   │   ├── auth_handler.go  # 认证相关处理
│   │   └── chat_handler.go  # 聊天相关处理
│   ├── models/
│   │   ├── group.go         # 群组模型
│   │   ├── message.go       # 消息模型
│   │   └── user.go          # 用户模型
│   ├── protocol/
│   │   └── protocol.go      # 通信协议
│   ├── server/
│   │   ├── client_manager_impl.go # 客户端管理实现
│   │   └── server.go        # 服务端核心逻辑
│   └── types/
│       └── types.go         # 类型定义
```

## 编译和运行

### 编译

```bash
cd go-server
go build -o chatroom-server cmd/server/main.go
```

### 运行

Windows系统可以使用start.bat脚本启动：

```bash
start.bat
```

或者直接运行可执行文件：

```bash
./chatroom-server.exe
```

服务端默认仅监听本机回环地址 `127.0.0.1:12346`（可在 `cmd/server/main.go` 中修改）。

## 依赖

- Go 1.24.5+
- SQLite3

所有Go依赖已在 `go.mod` 文件中定义：

- github.com/google/uuid (用于生成群组ID)
- golang.org/x/crypto (用于Argon2密码哈希)
- modernc.org/sqlite (用于SQLite数据库支持)

## 数据库

服务端使用SQLite数据库存储用户、消息、好友和群组信息。数据库文件 (`chat.db`) 会在首次运行时自动创建，包含以下表：

1. `users` 表：存储用户信息
   - id: 用户ID
   - username: 用户名（唯一）
   - password: 密码（Argon2哈希）

2. `messages` 表：存储聊天消息
   - id: 消息ID
   - chat_type: 聊天类型（private/group）
   - from_user: 发送者
   - to_user: 接收者（私聊时使用）
   - gid: 群组ID（群聊时使用）
   - message: 消息内容
   - timestamp: 时间戳

3. `friends` 表：存储好友关系
   - user: 用户
   - friend: 好友

4. `groups` 表：存储群组信息
   - gid: 群组ID
   - group_name: 群组名称
   - owner: 群主
   - members: 群组成员（JSON格式）
   - created_at: 创建时间

## 协议

服务端使用自定义的JSON协议进行通信，包含RSA密钥交换和AES消息加密。

## 测试

### Go 单元测试

```bash
cd go-server
go test ./...
```

包含 Argon2 密码哈希兼容性测试（旧格式裸哈希迁移、无效哈希拒绝）。

### 使用 Python 客户端联调

将 `client.py` 中的 `SERVER_PORT` 改为 `12346`，之后使用 Python 客户端 (`client.py`) 连接到 Go 服务端进行测试。

> 注意：Go 服务端仅监听 `127.0.0.1`，请确保客户端与服务端在同一主机上运行。


## 加密存储与升级

使用与 Python 服务端相同的 AES-256-GCM 字段加密及 HMAC 用户名索引。密钥默认保存在 `chat.db.key`，可用 `CHATROOM_STORAGE_KEY_FILE` 指向外部密钥文件；密钥独立于 RSA 密钥。保留并单独备份对应密钥，遗失后无法恢复数据库。

启动时事务迁移旧数据并清理旧明文页，完成前不会监听端口；缺失、损坏或错误密钥会停止启动。迁移后的库不得交给旧服务端打开。协议 v2 未改变，v1.0.10 客户端可继续使用。SQLite 结构、记录及群 ID、关系索引、请求过期时间和数量仍可见；详情见 [存储说明](../docs/STORAGE_ENCRYPTION.md)。
