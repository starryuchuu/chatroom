# Go Chatroom Server

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
├── cmd/
│   └── server/
│       └── main.go          # 服务端主程序入口
├── internal/
│   ├── crypto/
│   │   └── crypto.go        # 加密相关功能
│   ├── database/
│   │   ├── database.go      # 数据库初始化
│   │   ├── user_queries.go  # 用户相关数据库操作
│   │   ├── message_queries.go # 消息相关数据库操作
│   │   ├── friend_queries.go # 好友相关数据库操作
│   │   └── group_queries.go # 群组相关数据库操作
│   ├── handlers/
│   │   ├── auth_handler.go  # 认证相关处理
│   │   └── chat_handler.go  # 聊天相关处理
│   ├── models/
│   │   ├── user.go          # 用户模型
│   │   ├── message.go       # 消息模型
│   │   └── group.go         # 群组模型
│   ├── protocol/
│   │   └── protocol.go      # 通信协议
│   ├── server/
│   │   ├── server.go        # 服务端核心逻辑
│   │   ├── client_manager_impl.go # 客户端管理实现
│   │   └── client_manager.go # 客户端管理接口
│   └── types/
│       └── types.go         # 类型定义
├── go.mod                   # Go模块定义
├── go.sum                   # Go模块校验和
├── README.md                # 本说明文件
├── start.bat                # Windows启动脚本
└── chatroom-server.exe      # 编译后的可执行文件
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

服务端默认监听端口 `12345`。

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

可以使用Python客户端 (`client.py`) 连接到Go服务端进行测试。
