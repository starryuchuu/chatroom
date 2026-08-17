package models

// Group 代表一个聊天群组
type Group struct {
	GID       string   `json:"gid"`
	GroupName string   `json:"group_name"`
	Owner     string   `json:"owner"`
	Members   []string `json:"members"`
}
