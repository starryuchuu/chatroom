package server

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/e2ee"
	"chatroom/internal/handlers"
	"chatroom/internal/protocol"
	"chatroom/internal/types" // 导入 types 包
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // 导入 SHA-1
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net"
	"time"
)

var privateKey *rsa.PrivateKey
var publicKeyPEM []byte
var clientManager types.ClientManager // 全局客户端管理器 (现在是接口类型)

// Start 启动TCP服务器并开始接受客户端连接
func Start(address string) {
	if err := handlers.RestorePendingRequests(); err != nil {
		log.Fatalf("无法恢复待处理申请: %v", err)
	}
	privateKey, publicKeyPEM = crypto.EnsureRSAKeys()
	clientManager = NewClientManager() // 初始化客户端管理器

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("无法在地址 %s 上启动服务器: %v", address, err)
	}
	defer listener.Close()
	log.Printf("服务器正在监听 %s", address)

	connections := make(chan struct{}, 128)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}
		log.Printf("接受来自 %s 的新连接", conn.RemoteAddr().String())
		select {
		case connections <- struct{}{}:
			go func() { defer func() { <-connections }(); handleConnection(conn) }()
		default:
			conn.Close()
		}
	}
}

// handleConnection 处理单个客户端连接
func handleConnection(conn net.Conn) {
	// 防御性 recover：即使某个 handler 出现 panic，也不能让整个服务器进程崩溃
	defer func() {
		if r := recover(); r != nil {
			log.Printf("event=connection_panic error_type=%T", r)
		}
	}()

	// 设置连接超时和 KeepAlive
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(3 * time.Minute)
	}
	conn = protocol.WrapConn(conn)
	authDeadline := time.Now().Add(30 * time.Second)
	conn.SetReadDeadline(authDeadline)

	var currentUsername string // 用于在连接关闭时移除客户端
	defer func() {
		if currentUsername != "" {
			clientManager.RemoveClient(currentUsername, conn)
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
	pubKeyMsg := map[string]interface{}{
		"type":         "public_key",
		"key":          string(publicKeyPEM),
		"protocol":     protocol.Version,
		"capabilities": []string{"message_sync", "e2ee_v1", "opaque_v1", "history_request_id", "message_receipts"},
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

	sessionKeyType, ok := sessionKeyMsg["type"].(string)
	if !ok || sessionKeyType != "session_key" {
		log.Printf("event=invalid_session_key_message")
		return
	}

	if version, ok := sessionKeyMsg["protocol"].(float64); !ok || version != protocol.Version {
		protocol.SendMsg(conn, map[string]interface{}{"type": "error", "message": "请升级客户端以使用受保护的协议"})
		return
	}
	keyStr, ok := sessionKeyMsg["key"].(string)
	if !ok {
		log.Printf("会话密钥字段格式错误")
		return
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(keyStr)
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
	if len(sessionKey) != 16 && len(sessionKey) != 24 && len(sessionKey) != 32 {
		protocol.SendMsg(conn, map[string]interface{}{"type": "error", "message": "无效的会话密钥"})
		return
	}
	protocol.EnableAuthentication(conn, sessionKey, true)
	log.Printf("与 %s 的会话密钥已成功建立", conn.RemoteAddr().String())

	// 3. 处理认证
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return
	}
	publicDigest := sha256.Sum256(publicDER)
	username, err := handlers.HandleAuth(conn, sessionKey, clientManager, handlers.AuthOptions{ServerID: hex.EncodeToString(publicDigest[:]), Deadline: authDeadline, KeepReservation: true})
	if username != "" {
		defer clientManager.ReleaseAuthentication(username, conn)
	}
	if err != nil || username == "" {
		log.Printf("认证失败或连接关闭: %v", err)
		return // 认证失败或客户端断开，关闭连接
	}

	// 如果认证成功，username将不会为空
	log.Printf("event=authentication_completed")

	// 加载用户的好友列表
	friends, err := database.LoadFriends(username)
	if err != nil {
		log.Printf("event=friend_snapshot_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "好友列表加载失败"})
		return
	}

	// 将客户端添加到管理器（原子地防止同一用户名重复登录）
	if !clientManager.AddClient(username, conn, sessionKey, friends) {
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "该用户已登录"})
		log.Printf("event=duplicate_login_rejected")
		return
	}
	currentUsername = username // Only an owned reservation may be removed on exit.
	var identity interface{}
	storedIdentity, err := database.GetE2EEIdentity(username)
	if err == nil && storedIdentity != "" {
		identity, err = e2ee.ParseBundle(storedIdentity)
	}
	if err != nil {
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "加密身份加载失败，请重试"})
		return
	}
	loginResult := map[string]interface{}{"type": "login_result", "success": true, "e2ee_identity": identity}
	account, err := database.GetOpaqueAccount(username)
	if err != nil {
		return
	}
	if account != nil {
		loginResult["opaque_backup"] = account.Backup
		loginResult["opaque_generation"] = account.Generation
	}
	if err := protocol.SendMsg(conn, loginResult); err != nil {
		return
	}
	protocol.EnableQueuedWrites(conn)
	if err := handlers.SendFriendsAndActivate(conn, username, clientManager); err != nil {
		log.Printf("event=friend_activation_failed error_type=%T", err)
		protocol.SendMsgWait(conn, map[string]interface{}{"type": "error", "message": "好友列表加载失败，请重新登录"})
		return
	}
	conn.SetReadDeadline(time.Now().Add(30 * time.Minute))

	// 广播在线用户列表更新
	clientManager.BroadcastMessage(map[string]interface{}{
		"type":  "online_users",
		"users": clientManager.GetOnlineUsernames(),
	})

	// 发送用户所属的群组列表
	if err := handlers.SendUserGroups(conn, username); err != nil {
		protocol.SendMsgWait(conn, map[string]interface{}{"type": "error", "message": "群组列表加载失败，请重新登录"})
		return
	}

	if err := sendHistory(conn, username, sessionKey); err != nil {
		log.Printf("历史同步失败: %v", err)
		protocol.SendMsgWait(conn, map[string]interface{}{"type": "error", "message": "历史同步失败，请重新登录"})
		return
	}

	// 认证后的消息循环
	handlers.SendPendingNotifications(conn, username)
	handlers.HandleClientMessages(conn, username, sessionKey, clientManager)
}
