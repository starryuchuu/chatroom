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
		`CREATE TABLE IF NOT EXISTS pending_friend_requests (requester TEXT NOT NULL,target TEXT NOT NULL,created_at REAL NOT NULL,PRIMARY KEY(requester,target))`,
		`CREATE TABLE IF NOT EXISTS pending_group_invites (gid TEXT NOT NULL,target TEXT NOT NULL,inviter TEXT NOT NULL,created_at REAL NOT NULL,PRIMARY KEY(gid,target))`,
		`CREATE INDEX IF NOT EXISTS pending_friends_target ON pending_friend_requests(target)`,
		`CREATE INDEX IF NOT EXISTS pending_invites_target ON pending_group_invites(target)`,
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
	for _, stmt := range []string{
		"CREATE INDEX IF NOT EXISTS messages_private_from ON messages(chat_type,from_user,id)",
		"CREATE INDEX IF NOT EXISTS messages_private_to ON messages(chat_type,to_user,id)",
		"CREATE INDEX IF NOT EXISTS messages_group ON messages(chat_type,gid,id)",
	} {
		if _, err := DB.Exec(stmt); err != nil {
			log.Fatalf("创建消息索引失败: %v", err)
		}
	}
	log.Println("数据库表已成功初始化。")
}
