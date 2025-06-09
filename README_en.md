# Simple Chat Application Project Description

[中文文档请点击这里](./README.md)

## 1. Project Overview
This project implements a simple chat application consisting of a server and a client.  
- **Server (server.py)**: Responsible for handling user registration, login, storing chat history, managing friend requests, and forwarding both group and private messages.
- **Client (client.py)**: Built using Tkinter, it provides a graphical interface for user login, registration, message sending/receiving, and friend management.

## 2. Environment Requirements
- **Python Version**: Recommended Python 3.7 or above.
- **Dependencies**:
  - Built-in modules: socket, threading, datetime, sqlite3, hashlib, logging, struct.
  - [pycryptodome](https://pycryptodome.readthedocs.io/): Provides AES encryption/decryption (install via `pip install pycryptodome`).
  - Tkinter: Usually included with Python; install separately if missing.

## 3. Project Directory Structure
```
c:\Users\Master\Documents\chat_program_branch\
│
├── server.py         # Server-side program which handles network connections, user authentication, data storage, etc.
├── client.py         # Client-side program built with Tkinter for GUI operations.
└── README.md         # Chinese version of the project description.
```
This document (README_en.md) provides a detailed English explanation parallel to the Chinese README.

## 4. Code Explanation

### 4.1 server.py
- **Functionality**:  
  - Uses socket to establish TCP network communication, listening on a designated port for client connections.
  - Utilizes threading to handle multiple client requests concurrently.
  - Uses SQLite to store user data, messages, and friend relationships.
  - Implements AES encryption/decryption to secure messages during transmission.
- **Key Functions**:
  - `recvall`, `send_msg`, `recv_msg`: Helper functions to ensure complete message transmission by prefixing message lengths.
  - `encrypt_message`, `decrypt_message`: Encrypt and decrypt messages using AES (with Base64 encoding for transmission).
  - `init_db`: Initializes the SQLite database and creates the required tables for users, messages, and friends.
  - `handle_client`: Processes each client connection on a separate thread to manage registration, login, message forwarding, and friend management.
  - `main`: Entry point of the server that listens continuously for incoming client connections.

### 4.2 client.py
- **Functionality**:
  - Provides a graphical user interface based on Tkinter for login, registration, and chatting.
  - Uses socket to connect to the server, send encrypted messages, and receive decrypted messages.
  - Supports sending friend requests/responses, maintaining an online user list, and handling both private and group chats.
- **Key Functions**:
  - `build_login`: Constructs the login interface where users input their username and password.
  - `build_chat`: Constructs the main chat interface, including sections for friend lists, online user display, chat area, and message input.
  - `send_msg` and `receive_msg`: Handle sending (with encryption) and receiving (with decryption) messages.
  - `handle_friend_request` and `handle_friend_response`: Manage the friend request/response feature with user confirmation.

## 5. Running Instructions

### 5.1 Starting the Server
1. Open a terminal (Command Prompt) and navigate to the project directory.
2. Run the following command:
   ```
   python server.py
   ```
3. The server will start and log relevant information in the terminal while waiting for client connections.

### 5.2 Starting the Client
1. Open another terminal and navigate to the project directory.
2. Run the following command:
   ```
   python client.py
   ```
3. The client application will launch a window displaying the login screen. Enter your username and password to log in; if you are a new user, click "Register" to create an account.

## 6. Precautions
- **Avoiding Duplicate Logins**:  
  The server prevents multiple simultaneous logins for the same user account.
- **Encrypted Transmission**:  
  All messages are encrypted using AES to ensure secure communication over the network.
- **Database Permissions**:  
  The application creates or uses the `chat.db` SQLite file in the current directory. Ensure the application has read/write access.
- **Logging**:  
  Detailed logs are maintained during runtime for debugging and error tracking.

## 7. Development Suggestions
- Read the inline comments for a detailed understanding of each function and module.
- If additional features (such as file transfer or emoji support) are needed, consider extending the current codebase.
- [Project Homepage](https://github.com/username/repo) provides further details and potential updates.

## 8. FAQ
- **Server not starting or port occupied**:  
  Verify if the designated port is free or try a different port.
- **Client connection issues**:  
  Ensure the server is running and reachable, and that the SERVER_HOST and SERVER_PORT are configured correctly.
- **Database connection errors**:  
  Confirm the project directory has the necessary permissions and the SQLite3 installation is functioning properly.

## License

This project is licensed under the MIT License.
