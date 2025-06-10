# Simple Chatroom v1.0.1
[中文文档请点击这里](./README.md)
## Project Overview
This project is a simple chatroom implemented in Python, including both server and client. It supports multi-user registration, login, group chat, private chat, friend management, and now features an AI chat bot (AI_Bot).

## Main Features
- Multi-user registration and login, prevent duplicate login
- Group and private chat, AES encrypted message transmission
- Friend request, response, and management
- Local persistent chat history, support for message history
- New AI_Bot: chat with AI
- Graphical client (Tkinter), modern and user-friendly

## Requirements
- Python 3.7+
- Dependencies:
  - socket, threading, datetime, sqlite3, hashlib, logging (built-in)
  - struct (message packaging, built-in)
  - pycryptodome (`pip install pycryptodome`)
  - openai (`pip install openai`, required for AI_Bot)
  - Tkinter (usually built-in, may require manual install on some systems)

## Directory Structure
```
chatroom_v1.0.1/
├── server_v1.0.1.py   # Server code
├── client_v1.0.1.py   # Client code
├── README_zh.md       # 中文说明
├── README_en.md       # English README
```

## How to Run
### Start Server
1. Open command prompt, go to project directory
2. Run:
   ```
   python server_v1.0.1.py
   ```

### Start Client
1. In another command prompt, go to project directory
2. Run:
   ```
   python client_v1.0.1.py
   ```

## Notes
- Default database file is `chat.db`, ensure read/write permission
- All messages are AES encrypted for security
- Logs are output to terminal for debugging
- AI_Bot requires API Key (for online AI service)

## FAQ
- Port in use: check or change the port
- Connection failed: ensure server is running and network is OK
- Database error: check write permission or sqlite3 installation

## Release
### What's Changed (v1.0.1)
- Added AI_Bot chat bot, support for AI conversation
- Improved friend management protocol, with failure prompts
- Optimized chat history structure, support for message history
- UI improvements for better experience
- Code structure and comments improved
