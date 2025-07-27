package main

import (
	"chatroom/internal/database"
	"log"
)

func main() {
	log.Println("正在启动聊天服务器...")

	// 初始化数据库
	database.InitDB("./chat.db")

	log.Println("服务器已成功初始化。")
	// 在这里启动TCP服务器... (后续实现)
}
