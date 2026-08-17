package models

// Message 代表一条聊天消息
type Message struct {
	ID        int    `json:"id"`
	ChatType  string `json:"chat_type"` // "private" or "group"
	FromUser  string `json:"from_user"`
	ToUser    string `json:"to_user,omitempty"` // 私聊时使用
	GID       string `json:"gid,omitempty"`     // 群聊时使用
	Content   string `json:"content"`
	Timestamp string `json:"timestamp"`
}
