# Go Chatroom Server

## 当前版本：v1.3.4，传输协议 v2 + OPAQUE 单密码认证

单密码认证需要 v1.3.0 或更新的 Python 客户端和 Go 服务端；v1.3.4 配套客户端修复同页注册、键盘操作和消息状态恢复；Go 服务端仅同步版本号，业务代码与 v1.3.3 相同。正常注册、登录只输入一个统一密码，通过 OPAQUE 认证后在客户端解锁随机生成的聊天身份，服务器不接收正常登录密码，也不接收明文身份私钥。新版客户端要求 `e2ee_v1` 与 `opaque_v1`；连接旧服务器会停止，不回退到旧密码登录。

完整传输报文继续使用 HMAC-SHA256 认证及独立方向序号，RSA/AES-GCM 用于传输密钥交换与加密。私聊和群聊保持端到端加密，Go 服务端只验证公开签名并保存、转发密文，不能解开正文。路由及成员元数据仍可见，旧历史仍标记为非端到端加密；此聊天协议仍不提供针对长期接收私钥日后泄露的前向保密。详情见[端到端加密、备份与限制](../docs/END_TO_END_ENCRYPTION.md)。

旧账号需在登录页使用 **迁移旧账号…**，提供旧登录密码、原本机密钥口令和 8–128 个字符的新统一密码；新密码必须与旧登录密码不同。从未启用端到端加密的账号才可留空旧本机口令。只有这项显式迁移会通过已认证的加密传输验证旧密码；旧身份必须保持不变。未迁移账号仍可通过旧客户端登录，迁移后及新注册账号拒绝旧认证。新版客户端不支持 v1.2.x 服务端，详情见[单密码指南](../docs/SINGLE_PASSWORD.md)及[兼容说明](PROTOCOL_COMPATIBILITY.md)。

客户端可通过 **修改账号密码…** 保留身份并更新统一密码。服务器保存的云备份仅含加密身份，不包含联系人核验、群收件人批准及重放记录；云恢复不覆盖本机信任。v2 本机双层密钥库支持改密后保留并恢复原信任状态。新设备恢复身份后仍需核验联系人；完整离线备份另用统一密码和 Argon2id/AES-GCM 保护，改密后应重新导出。密码和全部恢复材料都丢失时，服务器不保证恢复历史消息。

Go 与 Python 共用 `opaque-ke` 4.0.1 的 RFC 9807 OPAQUE WASM 核心（Ristretto255、TripleDH-SHA512、Argon2id）。上游有历史审计记录，不代表该精确版本、WASM 产物或本项目集成已经独立审计。Go 通过 wazero 运行嵌入的模块；Python 使用 `wasmtime==50.0.1`。普通源码包已经带预编译 WASM，Python 安装 `requirements.txt` 后即可运行，无需 Rust；仅重建核心时需要 Rust 1.87+、`wasm32-unknown-unknown` 目标和根目录的 `python scripts/build_opaque.py`。

默认监听 `127.0.0.1:12346`，在客户端选择 Go 服务器配置或填入端口 `12346`。从 v1.3.0 以前升级时，旧数据库启动后自动增加 OPAQUE 元数据和账号表，保留原有账号和消息；这不会自动迁移旧账号凭据。升级前备份数据库、`chat.db.key`、服务器 RSA 密钥对以及客户端离线密钥备份。OPAQUE setup 与账号记录必须一同保留；存在账号但缺失 setup 时拒绝启动，不生成替代身份。

好友申请与群邀请重启后恢复，24 小时后过期。登录及入群最多同步 100 条最近历史，客户端支持加载更早的消息；发送群历史时重新检查成员资格并与踢人、退出、解散共用锁。群组登录快照及大快照分包也与群操作同步。

认证失败限制为同 IP 5 次/60 秒，最多 4 个并发认证和 128 个连接，成功认证不清空失败记录。消息保存确认继续代表数据库提交，不代表对方已读。

v1.3.2 对旧认证登录、OPAQUE 登录和迁移在凭据验证通过后共用在线账号预留，未完成密码证明的登录不会占住账号，在写入迁移结果前拒绝冲突，失败或断开时释放预留，避免提交迁移后才报重复登录。异常报文日志只记录安全事件，不再写入完整报文；日志调整不隐藏服务器可见的路由等元数据。

每群最多 256 位实际成员（含群主），创建、邀请和接受邀请均检查容量。邀请不预留名额，群满时保留尚未过期的邀请，容量释放后可重试；已有超限群可通过退群或移除成员缩减。建群先有界校验原始成员列表和用户名，再去重、批量查询，避免无效大列表占用群操作锁。

仅在 RSA 公钥与私钥均不存在时生成新身份。公钥仍存在而私钥丢失时，启动会停止，需从备份恢复原 `private_key.pem`；恢复后客户端固定的公钥指纹保持有效。私钥在 POSIX 系统上以 `0600` 权限创建，启动时也会收紧已有私钥的权限。

## 下载与验证

在 [v1.3.4 发布页](https://github.com/starryuchuu/chatroom/releases/tag/v1.3.4) 下载，详见 [发布说明](RELEASE_NOTES.md)。发布程序支持 Windows、Linux、macOS 的 amd64 与 arm64，默认监听 `127.0.0.1:12346`，可使用 v1.3.0 或更新的 Python 客户端；OPAQUE WASM 已嵌入可执行文件，无需另外安装 WASM 运行时。

```bash
go test ./...
go vet ./...
# Linux 上检查并发数据竞争
go test -race ./...
```

这是一个用Go语言编写的聊天室服务端，具有以下功能：

## 功能特性

- OPAQUE 单密码注册、登录、旧账号迁移和改密
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
│   ├── opaqueauth/           # wazero 运行时与嵌入的 OPAQUE WASM
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

源码包包含预编译的 `internal/opaqueauth/opaque_core.wasm`；常规 Go 构建不需要 Rust。该文件与 Python 客户端使用同一构建产物，不能单独删除或以不匹配的版本替换。

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

- Go 1.27.3（推荐，CI / 发布固定；语言最低版本 1.26.0）
- SQLite3

所有Go依赖已在 `go.mod` 文件中定义：

- github.com/google/uuid (用于生成群组ID)
- golang.org/x/crypto (用于Argon2密码哈希)
- modernc.org/sqlite (用于SQLite数据库支持)
- github.com/tetratelabs/wazero (运行嵌入的共享 OPAQUE WASM)

推荐使用与 CI / 发布构建一致的 Go 1.27.3；`go.mod` 的语言最低版本为 1.26.0，工具链固定 `go1.27.3`。漏洞检查在本目录执行 `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./cmd/server`，它分析指定服务端入口的可达漏洞，不等于所有依赖或本项目已独立审计；维护约定见[贡献指南](../CONTRIBUTING.md)。

## 数据库

服务端使用SQLite数据库存储用户、消息、好友和群组信息。数据库文件 (`chat.db`) 会在首次运行时自动创建，包含以下表：

1. `users` 表：存储用户信息
   - id: 用户ID
   - username: 用户名（唯一）
   - password: 加密的旧 Argon2 哈希，或加密的 OPAQUE 账号标记

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

5. `opaque_meta` 表：保存加密的服务器 OPAQUE setup。

6. `opaque_accounts` 表：保存加密的注册记录、identity-only 身份备份和用于并发更新检查的 generation。账号迁移、改密使用原子更新；不会替换已登记的端到端身份。

## 协议

服务端使用自定义 JSON 协议，保留 RSA 密钥交换、AES-GCM 和完整报文 HMAC 认证。`opaque_v1` 是同一传输上的新增认证能力，并不意味着旧客户端可以登录已升级账号。注册、登录和改密共用受限认证入口及整个交换的超时预算。

## 测试

### Go 单元测试

```bash
cd go-server
go test ./...
```

包含 Argon2 密码哈希兼容性测试（旧格式裸哈希迁移、无效哈希拒绝）。

### 使用 Python 客户端联调

在 Python 客户端登录页选择 Go 服务器配置，或填入端口 `12346`。使用 v1.3.4 客户端验证新账号注册、登录、显式迁移、改密及同一数据库在 Python/Go 间切换后的身份恢复。

> 注意：Go 服务端仅监听 `127.0.0.1`，请确保客户端与服务端在同一主机上运行。


## 加密存储与升级

使用与 Python 服务端相同的 AES-256-GCM 字段加密及 HMAC 用户名索引。密钥默认保存在 `chat.db.key`，可用 `CHATROOM_STORAGE_KEY_FILE` 指向外部密钥文件；密钥独立于 RSA 密钥。保留并单独备份对应密钥，遗失后无法恢复数据库。

从 v1.3.0 / v1.3.1 / v1.3.2 / v1.3.3 升到 v1.3.4 不改变数据库结构、传输或密钥格式，无需再次迁移已升级账号。停止旧进程并备份数据库和密钥后替换服务端，保留 OPAQUE setup、账号记录及原 RSA 身份。从 v1.3.0 以前升级仍须遵循[单密码迁移说明](../docs/SINGLE_PASSWORD.md)。

启动时事务迁移旧数据并清理旧明文页，完成前不会监听端口；缺失、损坏或错误密钥会停止启动。迁移后的库不得交给旧服务端打开。传输 v2 保留，但单密码账号要求 OPAQUE；旧客户端仅兼容尚未迁移的账号。新增 OPAQUE setup、注册记录和身份备份同样采用字段加密，服务器不能用其代替用户密码解锁身份。SQLite 结构、记录及群 ID、关系索引、请求过期时间和数量仍可见；详情见 [存储说明](../docs/STORAGE_ENCRYPTION.md)。
