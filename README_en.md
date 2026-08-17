# Encrypted Chat Room

[中文文档](./README.md) | [Go Server Documentation](./go-server/README.md)

## Project Overview

This project is a secure encrypted chat room system implemented in both Python and Go, featuring end-to-end encryption using modern cryptographic techniques (RSA+AES-GCM). The system supports multiple features including user registration, login, group chat, private chat, friend management, and group management. All messages are persisted in SQLite database, and sensitive information (such as passwords) is securely stored using the Argon2 hashing algorithm.

## Key Features

- 🔒 **Security**
  - End-to-end encrypted communication using RSA-3072 for key exchange
  - AES-GCM mode encryption for all messages
  - Argon2id password hashing with random salt
  - Secure session key management
  - Server public key fingerprint verification (anti-MITM)
  - Encrypted login (credentials transmitted via AES-GCM)

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

- 🖼️ **Interface Showcase**
  - Login Interface
    ![Login Interface](images/login%20in.PNG)
  - Main Page
    ![Main Page](images/main%20page.png)
  - Chat Interface
    ![Chat Interface](images/chat.PNG)

- 🛠 **Technical Stack**
  - Python 3.11+ (Client/Server)
  - Tkinter (GUI interface)
  - pycryptodome (Encryption features)
  - argon2-cffi (Password hashing)
  - Go 1.24+ (Server, toolchain `go1.24.5`)
  - SQLite3 (Data storage)
  - Built-in modules (socket, threading, datetime, logging, etc.)

## Security Design

- All messages are encrypted with AES-GCM, session key is dynamically generated per login
- Session key is securely exchanged using RSA public key encryption between client and server
- User passwords are stored using Argon2 hash algorithm
- All user, message, friend, and group info are persisted in SQLite database

## Environment Requirements

### Python Client/Server
- Python 3.11 or higher
- Required modules:
  - socket, threading, datetime, sqlite3, hashlib, logging (built-in)
  - struct, json (built-in)
  - pycryptodome (AES, RSA encryption/decryption, install via `pip install pycryptodome`)
  - argon2-cffi (password hashing, install via `pip install argon2-cffi`)
  - Tkinter (GUI, usually built-in, may require separate installation on some systems)

### Go Server
- Go 1.24.5 or higher
- Required modules (automatically managed by Go modules):
  - github.com/google/uuid (for generating group IDs)
  - golang.org/x/crypto (for Argon2 password hashing)
  - modernc.org/sqlite (for SQLite database support)

## Directory Structure

```
chatroom/
├── client.py                          # Python client code (group chat/session key/group management/GUI)
├── server.py                          # Python server code (group chat/session key/group management/database persistence)
├── requirements.txt                   # Python dependency list
├── go-server/                         # Go language implementation of the server
│   ├── README.md                      # Go server documentation
│   ├── go.mod / go.sum                # Go module definition and checksums
│   ├── chatroom-server.exe            # Precompiled Windows executable
│   ├── start.bat                      # Windows startup script
│   ├── cmd/server/main.go             # Server main program entry point
│   └── internal/
│       ├── crypto/                    # Encryption module
│       ├── database/                  # Database operations (incl. Argon2id hashing)
│       ├── handlers/                  # Request handlers (auth/chat)
│       ├── models/                    # Data models
│       ├── protocol/                  # Communication protocol
│       ├── server/                    # Server core logic
│       └── types/                     # Type definitions
├── images/                            # Interface screenshots
├── tests/                             # Tests and vulnerability verification scripts
│   ├── test_python_fixes.py           # Python security fix unit tests
│   ├── verify_recv_msg_len.py         # Message length limit verification script
│   ├── e2e_verify.py                  # End-to-end verification (mocked crypto deps)
│   ├── protocol_test.go               # Go protocol message length limit tests
│   └── mocks/                         # Test mocks (Crypto / argon2)
├── .github/workflows/                 # GitHub Actions workflows
│   └── build-executables.yml          # Cross-platform auto build
├── README.md                          # Chinese documentation
├── README_en.md                       # English README
├── GROUP_FEATURES_GUIDE.md            # Group features guide
└── LICENSE                            # GNU GPL v3 License
```

## Testing

### Python Tests

```bash
# Security fix unit tests (client fingerprint / friend request lock)
python tests/test_python_fixes.py

# Message length limit vulnerability verification (no external deps required)
python tests/verify_recv_msg_len.py

# End-to-end verification (uses mock crypto deps in tests/mocks, starts real server.py)
python tests/e2e_verify.py
```

> `tests/mocks/` provides lightweight mocks for `Crypto` and `argon2`, allowing the
> security verification scripts to run without installing the crypto dependencies.

### Go Tests

```bash
cd go-server
go test ./...          # Run all Go server tests (incl. Argon2 password hashing)
```

## Database Information

The database file (`chat.db`) will be automatically created when the Go server is run for the first time.

## Database Structure

The system uses an SQLite database to store user, message, friend, and group information, including the following tables:

1. `users` table: Stores user information
   - id: User ID
   - username: Username (unique)
   - password: Password (Argon2 hash)

2. `messages` table: Stores chat messages
   - id: Message ID
   - chat_type: Chat type (private/group)
   - from_user: Sender
   - to_user: Receiver (used for private chat)
   - gid: Group ID (used for group chat)
   - message: Message content
   - timestamp: Timestamp

3. `friends` table: Stores friend relationships
   - user: User
   - friend: Friend

4. `groups` table: Stores group information
   - gid: Group ID
   - group_name: Group name
   - owner: Group owner
   - members: Group members (JSON format)
   - created_at: Creation time

## Running Instructions

### Python Server

```bash
python server.py
```

The server will automatically generate RSA key pair (private_key.pem and public_key.pem) on first startup.

### Go Server

On Windows systems, you can use the start.bat script to start:

```bash
cd go-server
start.bat
```

Or run the executable directly:

```bash
cd go-server
./chatroom-server.exe
```

**Linux/macOS:** (build first)

```bash
cd go-server
go build -o chatroom-server ./cmd/server/main.go
./chatroom-server
```

Both servers only listen on `127.0.0.1` by default for security.

### Client

```bash
python client.py
```

The client connects to `127.0.0.1:12345` (Python server) by default. Modify the constants at the top of `client.py`:

| Scenario | Change |
|----------|--------|
| Connect to Go server | `SERVER_PORT = 12346` |
| Connect to a remote server | Set `SERVER_HOST` to the target IP or domain |
| Connect to a non-local server (production) | Set `EXPECTED_SERVER_KEY_FINGERPRINT` to the server's public key fingerprint |

> ⚠️ When connecting to a non-local server, you **must** set
> `EXPECTED_SERVER_KEY_FINGERPRINT`, otherwise the client will refuse the connection
> (anti-MITM). Obtain the fingerprint from the server log after your first local connection.

## Notes

- The Python server default port is `12345` (listens on `127.0.0.1`)
- The Go server default port is `12346` (listens on `127.0.0.1`)
- The database file (`chat.db`) will be automatically created on first run
- All messages are AES-GCM encrypted for security
- Session key is exchanged via RSA-3072 public key encryption
- Login credentials are transmitted encrypted (`encrypted_login` protocol)
- User passwords are stored using Argon2id + random salt hash algorithm
- Friend relationships are bidirectional
- Group owners cannot directly leave the group chat and must disband the group or transfer ownership first
- Security limits: max message 1 MB, auth timeout 30s, session timeout 30min, rate limit 5/60s
- Log information is output to the terminal for debugging

## Common Issues

- Port occupied: Check if the port is in use or change the port constant (`server.py` / `main.go`)
- Connection failure: Ensure the server is running and the network is operational, and that client port matches the server (Python `12345`, Go `12346`)
- "Server public key fingerprint not configured" refusal: set `EXPECTED_SERVER_KEY_FINGERPRINT` when connecting to a non-local server
- Database errors: Verify write permissions or check sqlite3 installation
- Group chat issues: Ensure group members are correct, owner cannot leave group directly

## Highlights
- End-to-end encryption: AES-GCM for messages, session key exchanged via RSA-3072 public key
- Password security: Argon2id + random salt hash for user passwords
- Anti-MITM: server public key fingerprint verification
- Encrypted login: credentials transmitted via AES-GCM
- Security hardening: rate limiting, message length limit, connection timeouts
- Group features: group creation, invitation, join, kick, owner management, persistent group info
- Advanced group features: group disbanding, ownership transfer, group name modification
- All messages use structured JSON protocol
- Robust error handling and logging
- Bilingual support (Chinese/English)
- Dual server implementation (Python/Go)
- GitHub Actions cross-platform automated builds
