package database

import (
	"database/sql"
	"log"
	"os"

	_ "modernc.org/sqlite"
)

// DB 是一个全局的数据库连接池
var DB *sql.DB

// InitDB 初始化数据库连接并创建表
func InitDB(dataSourceName string) {
	if err := OpenDB(dataSourceName); err != nil {
		log.Fatalf("无法初始化数据库: %v", err)
	}
}

// OpenDB returns startup/migration failures without rotating a missing encryption key.
func OpenDB(dataSourceName string) error {
	var err error
	DB, err = sql.Open("sqlite", dataSourceName)
	if err != nil {
		return err
	}

	// SQLite serializes writes. One reusable connection avoids SQLITE_BUSY
	// between login snapshots and concurrently persisted requests/messages.
	DB.SetMaxOpenConns(1)
	DB.SetMaxIdleConns(1)
	if _, err = DB.Exec("PRAGMA busy_timeout=5000"); err != nil {
		DB.Close()
		return err
	}
	if err = DB.Ping(); err != nil {
		DB.Close()
		return err
	}

	if err = os.Chmod(dataSourceName, 0600); err != nil {
		DB.Close()
		return err
	}
	for _, pragma := range []string{"PRAGMA secure_delete=ON", "PRAGMA temp_store=MEMORY"} {
		if _, err = DB.Exec(pragma); err != nil {
			DB.Close()
			return err
		}
	}
	if err = createTables(); err == nil {
		err = initializeStorage(dataSourceName)
	}
	if err != nil {
		DB.Close()
	}
	return err
}

// createTables 创建所有需要的表
func createTables() error {
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
			return err
		}
	}
	for _, stmt := range []string{
		"CREATE INDEX IF NOT EXISTS messages_private_from ON messages(chat_type,from_user,id)",
		"CREATE INDEX IF NOT EXISTS messages_private_to ON messages(chat_type,to_user,id)",
		"CREATE INDEX IF NOT EXISTS messages_group ON messages(chat_type,gid,id)",
	} {
		if _, err := DB.Exec(stmt); err != nil {
			return err
		}
	}
	log.Println("数据库表已成功初始化。")
	return nil
}
