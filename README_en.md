# Simple Chatroom v1.0.2
[中文文档请点击这里](./README.md)
## Project Overview
This project implements a simple chatroom based on Python, consisting of server and client components. It supports multiple user registration, login, group chat, private chat, friend management, and introduces an AI chatbot (AI_Bot) feature.

## Key Features
- Multi-user registration and login with duplicate login prevention
- Group and private chat with AES-encrypted message transmission
- Friend request, response, and management
- Local persistence of chat history with message retrieval
- Introduction of AI_Bot for AI conversations
- Graphical client (Tkinter) for a user-friendly experience
- Optimized chat interface with improved message display and scrolling experience

## Environment Requirements
- Python 3.7 or higher
- Required modules:
  - socket, threading, datetime, sqlite3, hashlib, logging (Built-in with Python)
  - struct (Message packet handling, built-in)
  - pycryptodome (AES encryption/decryption, install via `pip install pycryptodome`)
  - openai (AI chat, install via `pip install openai`, required for AI_Bot functionality)
  - Tkinter (GUI, usually built-in, may require separate installation on some systems)

## Directory Structure
```
chatroom_v1.0.2/
├── server_v1.0.2.py   # Server code
├── client_v1.0.2.py   # Client code
├── README_zh.md       # Chinese documentation
├── README_en.md       # English README
```

## Running Instructions
### Starting the Server
1. Open a command line and navigate to the project directory
2. Run:
   ```
   python server_v1.0.2.py
   ```

### Starting the Client
1. Open another command line window and navigate to the project directory
2. Run:
   ```
   python client_v1.0.2.py
   ```

## Notes
- The default database file is `chat.db`, ensure read/write permissions
- All messages are AES-encrypted for security
- Log information is output to the terminal for debugging purposes
- AI_Bot requires an API Key configuration (if using online AI services)

## Common Issues
- Port occupied: Check if the port is in use or change it
- Connection failure: Ensure the server is running and the network is operational
- Database errors: Verify write permissions or check sqlite3 installation

## Release Notes
### What's Changed (v1.0.2)
- Optimized client chat interface with improved message display logic and scrolling experience
- Enhanced AI service request retry mechanism for better AI_Bot response stability
- Further optimization of code structure and comments for improved readability

### What's Changed (v1.0.1)
- Introduced AI_Bot chatbot for AI conversations
- Optimized friend management protocol with failure notifications
- Improved chat history structure for message retrieval
- Enhanced client UI details for a better user experience
- Optimized code structure and comments
