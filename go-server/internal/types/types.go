package types

import (
	"net"
)

// ClientInfo 存储客户端连接的详细信息
type ClientInfo struct {
	Conn       net.Conn
	Username   string
	SessionKey []byte              // AES会话密钥
	Friends    map[string]struct{} // 好友列表, 使用空结构体作为值以节省空间
}

// ClientManager 定义了管理客户端连接的接口
type ClientManager interface {
	// AddClient 添加客户端；若用户名已在线则返回 false（拒绝重复登录）
	AddClient(username string, conn net.Conn, sessionKey []byte, friends map[string]struct{}) bool
	RemoveClient(username string)
	GetClient(username string) (*ClientInfo, bool)
	GetOnlineUsernames() []string
	BroadcastMessage(msg map[string]interface{})
	IsUserOnline(username string) bool
}
