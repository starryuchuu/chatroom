package database

import (
	"log"
)

// SaveFriendRelationship 保存两个用户之间的好友关系到数据库
func SaveFriendRelationship(user1, user2 string) error {
	tx, err := DB.Begin()
	if err != nil {
		log.Printf("event=save_friend_relationship_failed error_type=%T", err)
		return err
	}
	defer tx.Rollback() // 确保在函数退出时回滚，除非明确提交

	user1, err = storage.putName(tx, user1)
	if err != nil {
		return err
	}
	user2, err = storage.putName(tx, user2)
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO friends (user, friend) VALUES (?, ?)")
	if err != nil {
		log.Printf("event=save_friend_relationship_failed error_type=%T", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(user1, user2)
	if err != nil {
		log.Printf("event=save_friend_relationship_failed error_type=%T", err)
		return err
	}

	_, err = stmt.Exec(user2, user1)
	if err != nil {
		log.Printf("event=save_friend_relationship_failed error_type=%T", err)
		return err
	}

	// Either user's acceptance establishes the same relationship and consumes
	// both crossing requests in the transaction that creates the friendship.
	if _, err := tx.Exec("DELETE FROM pending_friend_requests WHERE (requester=? AND target=?) OR (requester=? AND target=?)", user2, user1, user1, user2); err != nil {
		return err
	}
	return tx.Commit() // 提交事务
}

// LoadFriends 从数据库加载用户的好友列表，并以map形式返回以便快速查找
func LoadFriends(username string) (map[string]struct{}, error) {
	rows, err := DB.Query("SELECT friend FROM friends WHERE user = ?", storage.token(username))
	if err != nil {
		log.Printf("event=load_friends_failed error_type=%T", err)
		return nil, err
	}
	defer rows.Close()

	friends := make(map[string]struct{})
	for rows.Next() {
		var friend string
		if err := rows.Scan(&friend); err != nil {
			log.Printf("event=load_friends_failed error_type=%T", err)
			continue
		}
		friends[friend] = struct{}{}
	}

	if err = rows.Err(); err != nil {
		log.Printf("event=load_friends_failed error_type=%T", err)
		return nil, err
	}
	rows.Close()
	decoded := make(map[string]struct{}, len(friends))
	for token := range friends {
		name, err := storage.name(token)
		if err != nil {
			return nil, err
		}
		decoded[name] = struct{}{}
	}
	return decoded, nil
}

// AreFriends 检查两个用户是否是好友关系
func AreFriends(user1, user2 string) (bool, error) {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM friends WHERE user = ? AND friend = ?", storage.token(user1), storage.token(user2)).Scan(&count)
	if err != nil {
		log.Printf("event=are_friends_failed error_type=%T", err)
		return false, err
	}
	return count > 0, nil
}
