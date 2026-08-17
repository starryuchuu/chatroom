package main

import (
	"chatroom/internal/database"
	"chatroom/internal/server"
	"log"
)

// 安全配置常量
const (
	ServerBindHost = "127.0.0.1" // 仅监听本地回环地址，防止外部访问
	ServerPort     = "12346"
)

func main() {
	log.Println("正在启动聊天服务器...")

	// 初始化数据库
	database.InitDB("./chat.db")

	log.Println("服务器已成功初始化。")

	// 启动 TCP 服务器 - 仅监听本地回环地址
	// 这将是一个阻塞操作，所以它会一直运行
	server.Start(ServerBindHost + ":" + ServerPort)
}
