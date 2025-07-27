package database

import (
	"log"
)

// SaveFriendRelationship 保存两个用户之间的好友关系到数据库
func SaveFriendRelationship(user1, user2 string) error {
	tx, err := DB.Begin()
	if err != nil {
		log.Printf("开始事务失败: %v", err)
		return err
	}
	defer tx.Rollback() // 确保在函数退出时回滚，除非明确提交

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO friends (user, friend) VALUES (?, ?)")
	if err != nil {
		log.Printf("准备好友关系语句失败: %v", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(user1, user2)
	if err != nil {
		log.Printf("执行保存好友关系失败 (user1->user2): %v", err)
		return err
	}

	_, err = stmt.Exec(user2, user1)
	if err != nil {
		log.Printf("执行保存好友关系失败 (user2->user1): %v", err)
		return err
	}

	return tx.Commit() // 提交事务
}

// LoadFriends 从数据库加载用户的好友列表，并以map形式返回以便快速查找
func LoadFriends(username string) (map[string]struct{}, error) {
	rows, err := DB.Query("SELECT friend FROM friends WHERE user = ?", username)
	if err != nil {
		log.Printf("查询好友列表失败: %v", err)
		return nil, err
	}
	defer rows.Close()

	friends := make(map[string]struct{})
	for rows.Next() {
		var friend string
		if err := rows.Scan(&friend); err != nil {
			log.Printf("扫描好友失败: %v", err)
			continue
		}
		friends[friend] = struct{}{}
	}

	if err = rows.Err(); err != nil {
		log.Printf("遍历好友结果集失败: %v", err)
		return nil, err
	}
	return friends, nil
}

// AreFriends 检查两个用户是否是好友关系
func AreFriends(user1, user2 string) (bool, error) {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM friends WHERE user = ? AND friend = ?", user1, user2).Scan(&count)
	if err != nil {
		log.Printf("检查好友关系失败 (%s, %s): %v", user1, user2, err)
		return false, err
	}
	return count > 0, nil
}
