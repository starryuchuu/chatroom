package handlers

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"chatroom/internal/types"
	"encoding/json"
	"errors"
	"log"
	"net"
	"time"
)

// HandleAuth 处理用户的认证请求（登录或注册）
// 成功后返回用户名，否则返回空字符串
var errRegistered = errors.New("注册成功，请重新登录")

type AuthOptions struct {
	ServerID string
	Deadline time.Time
	// The real server consumes a successful reservation in AddClient. Direct
	// protocol/test callers default to releasing it when HandleAuth returns.
	KeepReservation bool
}

func HandleAuth(conn net.Conn, sessionKey []byte, clientManager types.ClientManager, options ...AuthOptions) (username string, resultErr error) {
	settings := AuthOptions{Deadline: time.Now().Add(30 * time.Second)}
	if len(options) == 1 {
		settings = options[0]
	}
	ip := authIP(conn)
	if !reserveAuth(ip, time.Now()) {
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "请求过于频繁，请稍后再试"})
		return "", errors.New("authentication rate/concurrency limit")
	}
	defer func() {
		releaseAuth(ip, resultErr != nil && !errors.Is(resultErr, errRegistered) && !errors.Is(resultErr, errOpaqueHandled))
	}()
	// 循环以处理认证消息
	for {
		msg, err := protocol.RecvMsg(conn)
		if err != nil {
			return "", err
		}

		msgType, ok := msg["type"].(string)
		if !ok {
			log.Printf("收到的认证消息格式错误")
			continue
		}

		switch msgType {
		case "opaque_register_start", "opaque_login_start", "opaque_migrate_start", "opaque_change_start":
			return handleOpaque(conn, sessionKey, clientManager, msg, settings.ServerID, settings.Deadline, settings.KeepReservation)
		case "encrypted_register":
			return handleRegister(conn, sessionKey, msg)
		case "login":
			protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "不再支持明文登录，请升级客户端"})
			return "", errors.New("plaintext login rejected")
		case "encrypted_login":
			return handleEncryptedLogin(conn, sessionKey, clientManager, msg, settings.KeepReservation)
		default:
			log.Printf("Unknown authentication message rejected")
			// 可以选择发送一个错误消息给客户端
			protocol.SendMsg(conn, map[string]interface{}{
				"type":    "login_result",
				"success": false,
				"error":   "协议错误",
			})
			continue
		}
	}
}

func handleRegister(conn net.Conn, sessionKey []byte, msg map[string]interface{}) (string, error) {
	encryptedData, ok := msg["data"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": false, "error": "注册数据格式错误"})
		return "", errors.New("认证未通过")
	}

	decryptedData, err := crypto.DecryptMessage(encryptedData, sessionKey)
	if err != nil {
		log.Printf("Legacy registration decryption failed")
		protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": false, "error": "注册处理失败"})
		return "", errors.New("认证未通过")
	}

	var regInfo map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedData), &regInfo); err != nil {
		log.Printf("Legacy registration data rejected")
		protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": false, "error": "注册处理失败"})
		return "", errors.New("认证未通过")
	}

	username, ok := regInfo["from"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": false, "error": "注册数据格式错误"})
		return "", errors.New("认证未通过")
	}
	password, ok := regInfo["password"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": false, "error": "注册数据格式错误"})
		return "", errors.New("认证未通过")
	}

	err = database.RegisterUser(username, password)
	if err != nil {
		protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": false, "error": err.Error()})
		return "", errors.New("认证未通过") // 注册失败，关闭此次认证连接
	}

	protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": true})
	log.Printf("Legacy registration completed")
	// 注册后，客户端会断开连接，所以这里返回错误以便上层关闭连接
	return "", errRegistered
}

func handleLogin(conn net.Conn, clientManager types.ClientManager, msg map[string]interface{}, keepReservations ...bool) (string, error) {
	username, ok := msg["from"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "登录数据格式错误"})
		return "", errors.New("认证未通过")
	}
	password, ok := msg["password"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "登录数据格式错误"})
		return "", errors.New("认证未通过")
	}

	valid, err := database.ValidateUser(username, password)
	if err != nil {
		log.Printf("Legacy credential verification failed")
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "服务器内部错误"})
		return "", err // 内部错误，关闭连接
	}

	if valid {
		// Only proven credentials can occupy an account admission slot.
		if clientManager == nil || !clientManager.ReserveAuthentication(username, conn) {
			protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "该用户已登录"})
			log.Printf("Duplicate login rejected")
			return "", errors.New("该用户已登录")
		}
		keep := false
		defer func() {
			if !keep {
				clientManager.ReleaseAuthentication(username, conn)
			}
		}()
		// A migration may have committed and disconnected after the expensive
		// credential check. Once reserved, no other migration can start.
		account, err := database.GetOpaqueAccount(username)
		if err != nil || account != nil {
			protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "用户名或密码错误"})
			return "", errors.New("用户名或密码错误")
		}
		keep = len(keepReservations) == 1 && keepReservations[0]
		log.Printf("Legacy authentication completed")
		return username, nil // 登录成功，返回用户名
	}

	// 登录失败，返回错误以便上层关闭连接
	protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "用户名或密码错误"})
	return "", errors.New("用户名或密码错误") // 登录失败，关闭连接
}

// handleEncryptedLogin 处理加密登录（用户名/密码经 AES-GCM 会话密钥加密传输，避免明文暴露）
func handleEncryptedLogin(conn net.Conn, sessionKey []byte, clientManager types.ClientManager, msg map[string]interface{}, keepReservations ...bool) (string, error) {
	encryptedData, ok := msg["data"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "登录数据格式错误"})
		return "", errors.New("认证未通过")
	}

	decryptedData, err := crypto.DecryptMessage(encryptedData, sessionKey)
	if err != nil {
		log.Printf("Legacy login decryption failed")
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "登录数据处理失败"})
		return "", errors.New("认证未通过")
	}

	var loginInfo map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedData), &loginInfo); err != nil {
		log.Printf("Legacy login data rejected")
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "登录数据处理失败"})
		return "", errors.New("认证未通过")
	}

	return handleLogin(conn, clientManager, loginInfo, keepReservations...)
}
