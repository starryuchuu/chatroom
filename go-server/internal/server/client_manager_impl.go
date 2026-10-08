package server

import (
	"chatroom/internal/protocol"
	"chatroom/internal/types" // 导入 types 包
	"log"
	"net"
	"sync"
)

// clientManagerImpl 是 types.ClientManager 接口的具体实现
type clientManagerImpl struct {
	clients map[string]*types.ClientInfo // username -> ClientInfo
	mu      sync.RWMutex
}

// NewClientManager 创建并返回一个新的 types.ClientManager 实例
func NewClientManager() types.ClientManager {
	return &clientManagerImpl{
		clients: make(map[string]*types.ClientInfo),
	}
}

// AddClient reserves a username; it remains hidden until ActivateClient.
// 返回 false 表示用户名已在线（拒绝重复登录）
func (cm *clientManagerImpl) AddClient(username string, conn net.Conn, sessionKey []byte, friends map[string]struct{}) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if username == "" {
		return false
	}
	if _, exists := cm.clients[username]; exists {
		log.Printf("用户 '%s' 已在线，拒绝重复登录", username)
		return false
	}
	cm.clients[username] = &types.ClientInfo{
		Conn:       conn,
		Username:   username,
		SessionKey: sessionKey,
		Friends:    friends,
	}
	log.Printf("用户 '%s' 已上线。当前在线用户数: %d", username, len(cm.clients))
	return true
}

// ActivateClient publishes a session only after the login response is sent.
func (cm *clientManagerImpl) ActivateClient(username string, conn net.Conn) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	client, ok := cm.clients[username]
	if !ok || client.Conn != conn {
		return false
	}
	client.Ready = true
	return true
}

func (cm *clientManagerImpl) RemoveClient(username string, conn net.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if client, ok := cm.clients[username]; ok && client.Conn == conn {
		delete(cm.clients, username)
		log.Printf("用户 '%s' 已下线。当前在线用户数: %d", username, len(cm.clients))
	}
}

// GetClient 获取指定用户名的客户端信息
func (cm *clientManagerImpl) GetClient(username string) (*types.ClientInfo, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	client, ok := cm.clients[username]
	if !ok || !client.Ready {
		return nil, false
	}
	return client, true
}

// GetOnlineUsernames 获取所有在线用户的用户名列表
func (cm *clientManagerImpl) GetOnlineUsernames() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	usernames := make([]string, 0, len(cm.clients))
	for username, client := range cm.clients {
		if client.Ready {
			usernames = append(usernames, username)
		}
	}
	return usernames
}

// BroadcastMessage 向所有在线客户端广播消息
func (cm *clientManagerImpl) BroadcastMessage(msg map[string]interface{}) {
	cm.mu.RLock()
	clients := make([]*types.ClientInfo, 0, len(cm.clients))
	for _, client := range cm.clients {
		if client.Ready {
			clients = append(clients, client)
		}
	}
	cm.mu.RUnlock()
	for _, client := range clients {
		err := protocol.SendMsg(client.Conn, msg)
		if err != nil {
			log.Printf("向用户 '%s' 广播消息失败: %v", client.Username, err)
			// 可以在这里处理发送失败的客户端，例如将其标记为离线或移除
		}
	}
}

// IsUserOnline 检查用户是否在线
func (cm *clientManagerImpl) IsUserOnline(username string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	_, ok := cm.clients[username]
	return ok
}
