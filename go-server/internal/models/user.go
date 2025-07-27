package models

// User 代表一个用户
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"` // 密码不应被JSON序列化
}
