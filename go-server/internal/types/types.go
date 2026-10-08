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
	Ready      bool                // 登录响应已发送，可接收广播和其他用户消息
}

// ClientManager 定义了管理客户端连接的接口
type ClientManager interface {
	// AddClient reserves a username; activation follows the successful login reply.
	AddClient(username string, conn net.Conn, sessionKey []byte, friends map[string]struct{}) bool
	ActivateClient(username string, conn net.Conn) bool
	RemoveClient(username string, conn net.Conn)
	GetClient(username string) (*ClientInfo, bool)
	GetOnlineUsernames() []string
	BroadcastMessage(msg map[string]interface{})
	IsUserOnline(username string) bool
}
