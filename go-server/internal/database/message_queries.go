package database

import (
	"chatroom/internal/models"
	"database/sql"
	"log"
)

// SaveMessage 保存聊天消息到数据库
func SaveMessage(chatType, fromUser, toUser, gid, message, timestamp string) error {
	stmt, err := DB.Prepare(`
		INSERT INTO messages (chat_type, from_user, to_user, gid, message, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		log.Printf("准备保存消息语句失败: %v", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(chatType, fromUser, toUser, gid, message, timestamp)
	if err != nil {
		log.Printf("执行保存消息失败: %v", err)
		return err
	}
	return nil
}

// GetChatHistory 获取一个用户的完整聊天历史（私聊和群聊）
func GetChatHistory(username string) ([]models.Message, error) {
	var history []models.Message

	// 1. 获取用户所在的群组
	userGroups, err := GetUserGroups(username)
	if err != nil {
		return nil, err
	}

	// 2. 获取群聊历史
	if len(userGroups) > 0 {
		var gids []interface{}
		gidQueryPart := ""
		for i, group := range userGroups {
			gids = append(gids, group.GID)
			gidQueryPart += "?"
			if i < len(userGroups)-1 {
				gidQueryPart += ","
			}
		}

		query := `
			SELECT from_user, gid, message, timestamp, chat_type, to_user
			FROM messages
			WHERE chat_type='group' AND gid IN (` + gidQueryPart + `)
			ORDER BY id ASC
		`
		rows, err := DB.Query(query, gids...)
		if err != nil {
			log.Printf("查询群聊历史失败: %v", err)
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var msg models.Message
			var toUser, gid, fromUser, timestamp, chatType, message string
			// to_user 在群聊中为 NULL，所以需要处理
			var nullableToUser sql.NullString
			err := rows.Scan(&fromUser, &gid, &message, &timestamp, &chatType, &nullableToUser)
			if err != nil {
				log.Printf("扫描群聊历史行失败: %v", err)
				continue
			}
			if nullableToUser.Valid {
				toUser = nullableToUser.String
			}
			msg.FromUser = fromUser
			msg.GID = gid
			msg.Content = message
			msg.Timestamp = timestamp
			msg.ChatType = chatType
			msg.ToUser = toUser
			history = append(history, msg)
		}
	}

	// 3. 获取私聊历史
	query := `
		SELECT from_user, to_user, message, timestamp, chat_type, gid
		FROM messages
		WHERE chat_type='private' AND (from_user=? OR to_user=?)
		ORDER BY id ASC
	`
	rows, err := DB.Query(query, username, username)
	if err != nil {
		log.Printf("查询私聊历史失败: %v", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var msg models.Message
		var toUser, gid, fromUser, timestamp, chatType, message string
		var nullableGid sql.NullString
		err := rows.Scan(&fromUser, &toUser, &message, &timestamp, &chatType, &nullableGid)
		if err != nil {
			log.Printf("扫描私聊历史行失败: %v", err)
			continue
		}
		if nullableGid.Valid {
			gid = nullableGid.String
		}
		msg.FromUser = fromUser
		msg.ToUser = toUser
		msg.Content = message
		msg.Timestamp = timestamp
		msg.ChatType = chatType
		msg.GID = gid
		history = append(history, msg)
	}

	// 4. 对所有消息按时间戳排序 (如果需要跨类型排序)
	// 在这里，我们通过 ORDER BY id ASC 来保证顺序，这通常等同于时间顺序
	// 如果需要严格按时间戳字符串排序，可以使用 sort.Slice
	// sort.Slice(history, func(i, j int) bool {
	// 	return history[i].Timestamp < history[j].Timestamp
	// })

	return history, nil
}
