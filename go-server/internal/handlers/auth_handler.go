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
)

// HandleAuth 处理用户的认证请求（登录或注册）
// 成功后返回用户名，否则返回空字符串
func HandleAuth(conn net.Conn, sessionKey []byte, clientManager types.ClientManager) (string, error) {
	// 循环以处理认证消息
	for {
		msg, err := protocol.RecvMsg(conn)
		if err != nil {
			return "", err
		}

		msgType, ok := msg["type"].(string)
		if !ok {
			log.Printf("收到的认证消息格式错误: %v", msg)
			continue
		}

		switch msgType {
		case "encrypted_register":
			return handleRegister(conn, sessionKey, msg)
		case "login":
			return handleLogin(conn, clientManager, msg)
		case "encrypted_login":
			return handleEncryptedLogin(conn, sessionKey, clientManager, msg)
		default:
			log.Printf("未知的认证消息类型: %s", msgType)
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
		return "", nil
	}

	decryptedData, err := crypto.DecryptMessage(encryptedData, sessionKey)
	if err != nil {
		log.Printf("解密注册信息失败: %v", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": false, "error": "注册处理失败"})
		return "", nil
	}

	var regInfo map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedData), &regInfo); err != nil {
		log.Printf("解析注册JSON失败: %v", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": false, "error": "注册处理失败"})
		return "", nil
	}

	username, ok := regInfo["from"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": false, "error": "注册数据格式错误"})
		return "", nil
	}
	password, ok := regInfo["password"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": false, "error": "注册数据格式错误"})
		return "", nil
	}

	err = database.RegisterUser(username, password)
	if err != nil {
		protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": false, "error": err.Error()})
		return "", nil // 注册失败，继续等待下一个认证消息
	}

	protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": true})
	log.Printf("用户 %s 注册成功", username)
	// 注册后，客户端会断开连接，所以这里返回错误以便上层关闭连接
	return "", errors.New("注册成功，请重新登录")
}

func handleLogin(conn net.Conn, clientManager types.ClientManager, msg map[string]interface{}) (string, error) {
	username, ok := msg["from"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "登录数据格式错误"})
		return "", nil
	}
	password, ok := msg["password"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "登录数据格式错误"})
		return "", nil
	}

	// 检查用户是否已在线，防止重复登录造成身份混淆/劫持
	if clientManager.IsUserOnline(username) {
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "该用户已登录"})
		log.Printf("用户 %s 已在其他连接登录，拒绝重复登录", username)
		return "", errors.New("该用户已登录")
	}

	valid, err := database.ValidateUser(username, password)
	if err != nil {
		log.Printf("验证用户 %s 时出错: %v", username, err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "服务器内部错误"})
		return "", err // 内部错误，关闭连接
	}

	if valid {
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": true})
		log.Printf("用户 %s 登录成功", username)
		return username, nil // 登录成功，返回用户名
	}

	// 登录失败，返回错误以便上层关闭连接
	protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "用户名或密码错误"})
	return "", errors.New("用户名或密码错误") // 登录失败，关闭连接
}

// handleEncryptedLogin 处理加密登录（用户名/密码经 AES-GCM 会话密钥加密传输，避免明文暴露）
func handleEncryptedLogin(conn net.Conn, sessionKey []byte, clientManager types.ClientManager, msg map[string]interface{}) (string, error) {
	encryptedData, ok := msg["data"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "登录数据格式错误"})
		return "", nil
	}

	decryptedData, err := crypto.DecryptMessage(encryptedData, sessionKey)
	if err != nil {
		log.Printf("解密登录信息失败: %v", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "登录数据处理失败"})
		return "", nil
	}

	var loginInfo map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedData), &loginInfo); err != nil {
		log.Printf("解析登录JSON失败: %v", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "登录数据处理失败"})
		return "", nil
	}

	return handleLogin(conn, clientManager, loginInfo)
}
