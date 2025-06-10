# 简易聊天室 v1.0.1
[For English users, please refer to the README_en.md](./README_en.md)
## 项目简介
本项目实现了一个基于Python的简易聊天室，包含服务端和客户端两部分，支持多用户注册、登录、群聊、私聊、好友管理，并新增AI聊天机器人（AI_Bot）功能。

## 主要特性
- 多用户注册与登录，防止重复登录
- 群聊与私聊，消息AES加密传输
- 好友申请、响应与管理
- 聊天记录本地持久化，支持历史消息回溯
- 新增AI_Bot，支持与AI对话
- 图形化客户端（Tkinter），美观易用

## 环境依赖
- Python 3.7及以上
- 依赖模块：
  - socket、threading、datetime、sqlite3、hashlib、logging（Python内置）
  - struct（消息包处理，内置）
  - pycryptodome（AES加解密，`pip install pycryptodome`）
  - openai（AI聊天，`pip install openai`，如需AI_Bot功能）
  - Tkinter（GUI，通常已内置，部分系统需单独安装）

## 目录结构
```
chatroom_v1.0.1/
├── server_v1.0.1.py   # 服务端代码
├── client_v1.0.1.py   # 客户端代码
├── README_zh.md       # 中文说明
├── README_en.md       # English README
```

## 运行说明
### 启动服务端
1. 打开命令行，进入项目目录
2. 运行：
   ```
   python server_v1.0.1.py
   ```

### 启动客户端
1. 在另一命令行窗口进入项目目录
2. 运行：
   ```
   python client_v1.0.1.py
   ```

## 注意事项
- 默认数据库文件为`chat.db`，需有读写权限
- 所有消息均经AES加密，保障安全
- 日志信息输出于终端，便于调试
- AI_Bot需配置API Key（如需联网AI服务）

## 常见问题
- 端口被占用：请检查端口或更换
- 连接失败：请确认服务端已启动，网络正常
- 数据库异常：请确保有写权限，或检查sqlite3安装

## Release
### What's Changed (v1.0.1)
- 新增AI_Bot聊天机器人，支持与AI对话
- 优化好友管理协议，增加失败提示
- 聊天记录结构优化，支持历史消息回溯
- 客户端UI细节优化，体验更佳
- 代码结构与注释优化
