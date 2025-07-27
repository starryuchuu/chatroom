package server

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/handlers"
	"chatroom/internal/protocol"
	"chatroom/internal/types" // 导入 types 包
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // 导入 SHA-1
	"encoding/base64"
	"log"
	"net"
)

var privateKey *rsa.PrivateKey
var publicKeyPEM []byte
var clientManager types.ClientManager // 全局客户端管理器 (现在是接口类型)

// Start 启动TCP服务器并开始接受客户端连接
func Start(address string) {
	privateKey, publicKeyPEM = crypto.EnsureRSAKeys()
	clientManager = NewClientManager() // 初始化客户端管理器

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("无法在地址 %s 上启动服务器: %v", address, err)
	}
	defer listener.Close()
	log.Printf("服务器正在监听 %s", address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}
		log.Printf("接受来自 %s 的新连接", conn.RemoteAddr().String())
		go handleConnection(conn)
	}
}

// handleConnection 处理单个客户端连接
func handleConnection(conn net.Conn) {
	var currentUsername string // 用于在连接关闭时移除客户端
	defer func() {
		if currentUsername != "" {
			clientManager.RemoveClient(currentUsername)
			// 广播在线用户列表更新
			clientManager.BroadcastMessage(map[string]interface{}{
				"type":  "online_users",
				"users": clientManager.GetOnlineUsernames(),
			})
		}
		conn.Close()
		log.Printf("连接 %s 已关闭", conn.RemoteAddr().String())
	}()

	// 1. 发送公钥
	pubKeyMsg := map[string]string{
		"type": "public_key",
		"key":  string(publicKeyPEM),
	}
	if err := protocol.SendMsg(conn, pubKeyMsg); err != nil {
		log.Printf("发送公钥失败: %v", err)
		return
	}

	// 2. 接收加密的会话密钥
	sessionKeyMsg, err := protocol.RecvMsg(conn)
	if err != nil {
		log.Printf("接收会话密钥失败: %v", err)
		return
	}

	if sessionKeyMsg["type"] != "session_key" {
		log.Printf("期望接收会话密钥，但收到了: %s", sessionKeyMsg["type"])
		return
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(sessionKeyMsg["key"].(string))
	if err != nil {
		log.Printf("Base64解码会话密钥失败: %v", err)
		return
	}

	// 使用RSA私钥解密 (OAEP with SHA-1)
	sessionKey, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, encryptedKey, nil)
	if err != nil {
		log.Printf("解密会话密钥失败 (OAEP with SHA-1): %v", err)
		return
	}
	log.Printf("与 %s 的会话密钥已成功建立", conn.RemoteAddr().String())

	// 3. 处理认证
	username, err := handlers.HandleAuth(conn, sessionKey)
	if err != nil {
		log.Printf("认证失败或连接关闭: %v", err)
		return // 认证失败或客户端断开，关闭连接
	}

	// 如果认证成功，username将不会为空
	log.Printf("用户 %s 已通过认证", username)
	currentUsername = username // 记录当前连接的用户名

	// 加载用户的好友列表
	friends, err := database.LoadFriends(username)
	if err != nil {
		log.Printf("为用户 %s 加载好友列表失败: %v", username, err)
		// 即使加载失败，也让用户登录，好友列表将为空
		friends = make(map[string]struct{})
	}

	// 将客户端添加到管理器
	clientManager.AddClient(username, conn, sessionKey, friends)

	// 发送好友列表给客户端
	friendList := make([]string, 0, len(friends))
	for friend := range friends {
		friendList = append(friendList, friend)
	}
	friendListMsg := map[string]interface{}{
		"type":    "friends_list",
		"friends": friendList,
	}
	if err := protocol.SendMsg(conn, friendListMsg); err != nil {
		log.Printf("发送好友列表给 %s 失败: %v", username, err)
	} else {
		log.Printf("已成功发送 %d 个好友给用户 %s", len(friendList), username)
	}

	// 广播在线用户列表更新
	clientManager.BroadcastMessage(map[string]interface{}{
		"type":  "online_users",
		"users": clientManager.GetOnlineUsernames(),
	})

	// 发送用户所属的群组列表
	userGroups, err := database.GetUserGroups(username)
	if err != nil {
		log.Printf("无法为用户 %s 获取群组列表: %v", username, err)
		// 即使获取失败，也继续执行，不中断连接
	} else if len(userGroups) > 0 {
		groupsMsg := map[string]interface{}{
			"type":   "user_groups_list",
			"groups": userGroups,
		}
		if err := protocol.SendMsg(conn, groupsMsg); err != nil {
			log.Printf("发送群组列表给 %s 失败: %v", username, err)
		} else {
			log.Printf("已成功发送 %d 个群组给用户 %s", len(userGroups), username)
		}
	}

	// 发送聊天历史记录
	history, err := database.GetChatHistory(username)
	if err != nil {
		log.Printf("无法为用户 %s 获取聊天记录: %v", username, err)
	} else {
		log.Printf("正在为用户 %s 发送 %d 条历史消息...", username, len(history))
		for _, msg := range history {
			// 加密消息内容
			encryptedContent, err := crypto.EncryptMessage(msg.Content, sessionKey)
			if err != nil {
				log.Printf("加密历史消息失败 (from: %s): %v", msg.FromUser, err)
				continue
			}

			var histMsg map[string]interface{}
			if msg.ChatType == "group" {
				histMsg = map[string]interface{}{
					"type":      "group_chat",
					"from":      msg.FromUser,
					"gid":       msg.GID,
					"content":   encryptedContent,
					"timestamp": msg.Timestamp,
				}
			} else { // private
				histMsg = map[string]interface{}{
					"type":      "private_chat",
					"from":      msg.FromUser,
					"to":        msg.ToUser,
					"content":   encryptedContent,
					"timestamp": msg.Timestamp,
				}
			}

			if err := protocol.SendMsg(conn, histMsg); err != nil {
				log.Printf("发送历史消息给 %s 失败: %v", username, err)
				// 如果一条消息发送失败，可以选择中断或继续
				break
			}
		}
		log.Printf("历史消息发送完成 for %s", username)
	}

	// 认证后的消息循环
	handlers.HandleClientMessages(conn, username, sessionKey, clientManager)
}
