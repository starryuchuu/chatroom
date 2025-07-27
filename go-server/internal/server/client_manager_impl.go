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

// AddClient 添加一个客户端到管理器
func (cm *clientManagerImpl) AddClient(username string, conn net.Conn, sessionKey []byte, friends map[string]struct{}) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.clients[username] = &types.ClientInfo{
		Conn:       conn,
		Username:   username,
		SessionKey: sessionKey,
		Friends:    friends,
	}
	log.Printf("用户 '%s' 已上线。当前在线用户数: %d", username, len(cm.clients))
}

// RemoveClient 从管理器中移除一个客户端
func (cm *clientManagerImpl) RemoveClient(username string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if _, ok := cm.clients[username]; ok {
		delete(cm.clients, username)
		log.Printf("用户 '%s' 已下线。当前在线用户数: %d", username, len(cm.clients))
	}
}

// GetClient 获取指定用户名的客户端信息
func (cm *clientManagerImpl) GetClient(username string) (*types.ClientInfo, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	client, ok := cm.clients[username]
	return client, ok
}

// GetOnlineUsernames 获取所有在线用户的用户名列表
func (cm *clientManagerImpl) GetOnlineUsernames() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	usernames := make([]string, 0, len(cm.clients))
	for username := range cm.clients {
		usernames = append(usernames, username)
	}
	return usernames
}

// BroadcastMessage 向所有在线客户端广播消息
func (cm *clientManagerImpl) BroadcastMessage(msg map[string]interface{}) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	for _, client := range cm.clients {
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
