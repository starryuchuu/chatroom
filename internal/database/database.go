package database

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

// DB 是一个全局的数据库连接池
var DB *sql.DB

// InitDB 初始化数据库连接并创建表
func InitDB(dataSourceName string) {
	var err error
	DB, err = sql.Open("sqlite", dataSourceName)
	if err != nil {
		log.Fatalf("无法打开数据库: %v", err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatalf("无法连接到数据库: %v", err)
	}

	createTables()
}

// createTables 创建所有需要的表
func createTables() {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_type TEXT NOT NULL,
            from_user TEXT NOT NULL,
            to_user TEXT,
            gid TEXT,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS friends (
            user TEXT NOT NULL,
            friend TEXT NOT NULL,
            UNIQUE(user, friend)
        )`,
		`CREATE TABLE IF NOT EXISTS groups (
            gid TEXT PRIMARY KEY,
            group_name TEXT NOT NULL,
            owner TEXT NOT NULL,
            members TEXT NOT NULL,
            created_at TEXT NOT NULL
        )`,
	}

	for _, stmt := range statements {
		_, err := DB.Exec(stmt)
		if err != nil {
			log.Fatalf("无法创建表: %v", err)
		}
	}
	log.Println("数据库表已成功初始化。")
}
