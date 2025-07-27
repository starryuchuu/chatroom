package main

import (
	"chatroom/internal/database"
	"chatroom/internal/server"
	"log"
)

func main() {
	log.Println("正在启动聊天服务器...")

	// 初始化数据库
	database.InitDB("./chat.db")

	log.Println("服务器已成功初始化。")

	// 启动TCP服务器
	// 这将是一个阻塞操作，所以它会一直运行
	server.Start("0.0.0.0:12346")
}
