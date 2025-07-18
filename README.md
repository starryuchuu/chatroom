# 简易加密聊天室 / Encrypted Chat Room

[English README](./README_en.md)

## 项目简介
本项目是一个基于 Python 的安全加密聊天室，采用现代加密技术（RSA+AES-GCM）实现端到端加密通信。系统支持多用户注册、登录、群聊、私聊、好友管理和群组管理等功能，并使用 SQLite 数据库实现消息持久化存储。所有敏感信息（如密码）都经过安全的 Argon2 算法加密存储，保证用户数据安全。

## 主要特性
- 🔒 **安全性**
  - 端到端加密通信，使用 RSA 进行密钥交换
  - AES-GCM 模式加密所有消息内容
  - Argon2 算法加密存储用户密码
  - 安全的会话密钥管理机制

- 💬 **社交功能**
  - 支持私聊和群聊
  - 好友添加与管理
  - 群组创建与管理
  - 在线状态实时更新

- 💾 **数据管理**
  - SQLite 数据库持久化存储
  - 聊天历史记录查询
  - 用户信息管理
  - 群组信息维护

- 🎨 **用户体验**
  - 简洁直观的图形界面
  - 实时消息提醒
  - 群组成员管理
  - 良好的错误提示

- 🛠 **技术依赖**
  - Python 3.x
  - Tkinter (GUI界面)
  - pycryptodome (加密功能)
  - argon2-cffi (密码哈希)
  - SQLite3 (数据存储)
  - 其他内置模块 (socket, threading, datetime, logging等)

## 目录结构
```
chatroom/
├── server.py         # 服务端代码（支持群聊/密钥交换/群组管理/数据库持久化）
├── client.py         # 客户端代码（支持群聊/密钥交换/群组管理/GUI）
├── requirements.txt  # 依赖说明
├── README.md         # 中文说明
└── README_en.md      # English README
```

## 运行说明
### 1. 启动服务器
```bash
python server.py
```
服务器首次启动时会自动生成RSA密钥对（private_key.pem 和 public_key.pem）。

### 2. 启动客户端
```bash
python client.py
```


## 注意事项

## 常见问题
- 端口被占用：请检查端口或更换
- 连接失败：请确认服务端已启动，网络正常
- 数据库异常：请确保有写权限，或检查 sqlite3 安装
- 群聊相关问题：请确保群组成员正确，群主不可直接退出群聊

## 新增/改进功能
- 端到端加密：消息采用 AES-GCM 加密，密钥通过 RSA 公钥加密交换
- 密码安全：用户密码采用 Argon2 哈希算法存储
- 群组功能：支持群聊创建、邀请、加入、踢人、群主管理，群组信息持久化
- 聊天协议全面升级，所有消息均为结构化 JSON 格式
- 完善的错误处理与日志输出
- 代码结构和注释进一步优化，提升可读性
