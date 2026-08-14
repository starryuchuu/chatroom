# 🔐 加密聊天室 / Encrypted Chat Room

[English Version](./README_en.md) | [群组功能指南](./GROUP_FEATURES_GUIDE.md)

![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.x-green.svg)
![Go](https://img.shields.io/badge/go-1.24+-blue.svg)

---

## 📖 项目简介

本项目是一个**安全加密的即时通讯聊天室系统**，采用现代密码学技术实现端到端加密通信。系统提供完整的社交功能，包括私聊、群聊、好友管理等，同时确保所有通信内容和用户数据的安全性。

### ✨ 核心优势

- **🔒 端到端加密**：RSA 密钥交换 + AES-GCM 消息加密
- **🛡️ 密码安全**：Argon2 哈希算法存储用户密码
- **💬 丰富功能**：支持私聊、群聊、好友管理、群组管理
- **💾 数据持久化**：SQLite 数据库存储聊天记录和用户信息
- **🚀 双服务端**：Python 和 Go 两种实现，满足不同需求

---

## 🖼️ 界面预览

| 登录界面 | 主界面 | 聊天界面 |
|---------|--------|---------|
| ![登录界面](images/login%20in.PNG) | ![主界面](images/main%20page.png) | ![聊天界面](images/chat.PNG) |

---

## 🚀 快速开始

### 环境要求

- **Python 客户端**: Python 3.x
- **Python 服务端**: Python 3.x
- **Go 服务端**: Go 1.24+
- **操作系统**: Windows / Linux / macOS

### 安装依赖

```bash
pip install -r requirements.txt
```

### 启动服务端

#### 方式一：Python 服务端（端口 12345）

```bash
python server.py
```

> 首次启动时会自动生成 RSA 密钥对（`private_key.pem` 和 `public_key.pem`）

#### 方式二：Go 服务端（端口 12346）

**Windows:**
```bash
cd go-server
start.bat
```

**Linux/macOS:**
```bash
cd go-server
./chatroom-server
```

### 启动客户端

```bash
python client.py
```

---

## 📋 功能特性

### 🔒 安全特性

| 功能 | 说明 |
|------|------|
| RSA 密钥交换 | 安全的会话密钥协商机制 |
| AES-GCM 加密 | 所有消息内容加密传输 |
| Argon2 哈希 | 用户密码安全存储 |
| 会话密钥管理 | 动态密钥更新机制 |

### 💬 社交功能

- ✅ **私聊通信**：一对一加密聊天
- ✅ **群聊功能**：支持多人在线群聊
- ✅ **好友管理**：添加、删除好友，查看好友列表
- ✅ **群组管理**：创建群组、邀请成员、踢出成员
- ✅ **高级管理**：解散群组、转让群主、修改群名
- ✅ **在线状态**：实时显示用户在线状态

### 💾 数据管理

- 聊天历史记录持久化存储
- 用户信息和群组信息管理
- 好友关系维护（双向关系）
- SQLite 数据库高效存储

---

## 📁 项目结构

```
chatroom/
├── client.py                 # Python 客户端（GUI/加密/群聊）
├── server.py                 # Python 服务端（数据库/加密/群聊）
├── requirements.txt          # Python 依赖包
├── go-server/                # Go 服务端实现
│   ├── cmd/server/main.go    # 服务端入口
│   ├── internal/             # 内部模块
│   │   ├── crypto/           # 加密模块
│   │   ├── database/         # 数据库操作
│   │   ├── handlers/         # 请求处理器
│   │   ├── models/           # 数据模型
│   │   ├── protocol/         # 通信协议
│   │   ├── server/           # 服务端核心
│   │   └── types/            # 类型定义
│   └── start.bat             # Windows 启动脚本
├── images/                   # 界面截图
├── tests/                    # 测试文件
├── README.md                 # 中文文档
├── README_en.md              # 英文文档
└── GROUP_FEATURES_GUIDE.md   # 群组功能详解
```

---

## 🗄️ 数据库结构

系统使用 SQLite 数据库 (`chat.db`)，首次运行时自动创建。

### 数据表说明

#### 1. users（用户表）

| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER | 用户 ID（主键） |
| username | TEXT | 用户名（唯一） |
| password | TEXT | 密码（Argon2 哈希） |

#### 2. messages（消息表）

| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER | 消息 ID（主键） |
| chat_type | TEXT | 聊天类型（private/group） |
| from_user | TEXT | 发送者 |
| to_user | TEXT | 接收者（私聊） |
| gid | INTEGER | 群组 ID（群聊） |
| message | TEXT | 加密消息内容 |
| timestamp | DATETIME | 时间戳 |

#### 3. friends（好友表）

| 字段 | 类型 | 说明 |
|------|------|------|
| user | TEXT | 用户 |
| friend | TEXT | 好友 |

#### 4. groups（群组表）

| 字段 | 类型 | 说明 |
|------|------|------|
| gid | INTEGER | 群组 ID（主键） |
| group_name | TEXT | 群组名称 |
| owner | TEXT | 群主 |
| members | TEXT | 成员列表（JSON） |
| created_at | DATETIME | 创建时间 |

---

## ⚙️ 配置说明

### 默认端口

| 服务端 | 端口 |
|--------|------|
| Python 服务端 | 12345 |
| Go 服务端 | 12346 |

### 重要规则

- 🔐 所有消息均经过 AES-GCM 加密
- 🔑 用户密码使用 Argon2 哈希存储
- 👥 好友关系为双向绑定
- 👑 群主不能直接退出群聊，需先解散或转让
- 💾 数据库文件在首次运行时自动创建

---

## ❓ 常见问题

### 连接问题

**Q: 端口被占用怎么办？**  
A: 检查是否有其他程序占用端口，或修改服务端端口配置。

**Q: 连接失败？**  
A: 确认服务端已启动，检查防火墙设置和网络连接。

### 数据库问题

**Q: 数据库异常？**  
A: 确保应用有数据库文件的读写权限，检查 SQLite3 是否正确安装。

### 群聊问题

**Q: 无法退出群聊？**  
A: 群主需要先解散群聊或将群主身份转让给其他成员。

**Q: 群聊消息发送失败？**  
A: 检查群组成员列表是否正确，确认网络连接正常。

---

## 🆕 版本特性

### 最新功能

- ✅ 端到端加密通信（AES-GCM + RSA）
- ✅ Argon2 密码哈希存储
- ✅ 完整群组功能（创建/邀请/踢人/解散/转让）
- ✅ 结构化 JSON 通信协议
- ✅ 完善的错误处理和日志系统
- ✅ 双语支持（中文/英文）
- ✅ Python 和 Go 双服务端实现

---

## 📄 许可证

本项目采用 [GNU GPL v3](./LICENSE) 开源许可证。

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

---

## 📧 联系方式

如有问题或建议，请通过 Issue 反馈。
