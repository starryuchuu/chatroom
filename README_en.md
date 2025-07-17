# Encrypted Chat Room

[中文文档](./README.md)

## Project Overview
This project is a secure encrypted chat room system implemented in Python, featuring end-to-end encryption using modern cryptographic techniques (RSA+AES-GCM). The system supports multiple features including user registration, login, group chat, private chat, friend management, and group management. All messages are persisted in SQLite database, and sensitive information (such as passwords) is securely stored using the Argon2 hashing algorithm.

## Key Features
- 🔒 **Security**
  - End-to-end encrypted communication using RSA for key exchange
  - AES-GCM mode encryption for all messages
  - Argon2 algorithm for password hashing
  - Secure session key management

- 💬 **Social Features**
  - Support for private and group chat
  - Friend request and management
  - Group creation and management
  - Real-time online status updates

- 💾 **Data Management**
  - SQLite database persistence
  - Chat history retrieval
  - User information management
  - Group information maintenance

- 🎨 **User Experience**
  - Clean and intuitive graphical interface
  - Real-time message notifications
  - Group member management
  - User-friendly error handling

- 🛠 **Technical Stack**
  - Python 3.x
  - Tkinter (GUI interface)
  - pycryptodome (Encryption features)
  - argon2-cffi (Password hashing)
  - SQLite3 (Data storage)
  - Built-in modules (socket, threading, datetime, logging, etc.)

## Security Design
- All messages are encrypted with AES-GCM, session key is dynamically generated per login
- Session key is securely exchanged using RSA public key encryption between client and server
- User passwords are stored using Argon2 hash algorithm
- All user, message, friend, and group info are persisted in SQLite database

## Environment Requirements
- Python 3.12 or higher
- Required modules:
  - socket, threading, datetime, sqlite3, hashlib, logging (built-in)
  - struct, json (built-in)
  - pycryptodome (AES, RSA encryption/decryption, install via `pip install pycryptodome`)
  - argon2-cffi (password hashing, install via `pip install argon2-cffi`)
  - Tkinter (GUI, usually built-in, may require separate installation on some systems)

## Directory Structure
```
chatroom/
├── server.py         # Server code (group chat/session key/group management/database persistence)
├── client.py         # Client code (group chat/session key/group management/GUI)
├── requirements.txt  # Dependency list
├── README.md         # Chinese documentation
└── README_en.md      # English README
```

## Running Instructions
### 1. Start the server
```bash
python server.py
```
The server will automatically generate RSA key pair (private_key.pem and public_key.pem) on first startup.

### 2. Start the client
```bash
python server.py
```

### 3. Start the client
```bash
python client.py
```

## Notes
- The default database file is `chat.db`, ensure read/write permissions
- All messages are AES-GCM encrypted for security
- Session key is exchanged via RSA public key encryption
- User passwords are stored using Argon2 hash algorithm
- Log information is output to the terminal for debugging

## Common Issues
- Port occupied: Check if the port is in use or change it
- Connection failure: Ensure the server is running and the network is operational
- Database errors: Verify write permissions or check sqlite3 installation
- Group chat issues: Ensure group members are correct, owner cannot leave group directly

## develop branch highlights
End-to-end encryption: AES-GCM for messages, session key exchanged via RSA public key
Password security: Argon2 hash for user passwords
Group features: group creation, invitation, join, kick, owner management, persistent group info
All messages use structured JSON protocol
Robust error handling and logging
Further optimized code structure and comments for better readability
