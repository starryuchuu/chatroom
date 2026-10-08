package database

import (
	"chatroom/internal/models"
	"database/sql"
	"strings"
)

// SaveMessage keeps the existing API for callers that do not need a receipt.
func SaveMessage(chatType, fromUser, toUser, gid, message, timestamp string) error {
	_, err := SaveMessageWithID(chatType, fromUser, toUser, gid, message, timestamp)
	return err
}

// SaveMessageWithID returns the committed SQLite ID used in live and history frames.
func SaveMessageWithID(chatType, fromUser, toUser, gid, message, timestamp string) (int64, error) {
	result, err := DB.Exec(`INSERT INTO messages (chat_type, from_user, to_user, gid, message, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)`, chatType, fromUser, toUser, gid, message, timestamp)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func GetChatHistory(username string) ([]models.Message, error) {
	history, _, err := GetChatHistorySnapshot(username)
	return history, err
}

// GetChatHistorySnapshot uses one ID boundary and query for all conversations.
// Messages committed after the boundary are delivered through the online session.
func GetChatHistorySnapshot(username string) ([]models.Message, int64, error) {
	var boundary int64
	if err := DB.QueryRow("SELECT COALESCE(MAX(id), 0) FROM messages").Scan(&boundary); err != nil {
		return nil, 0, err
	}
	groups, err := GetUserGroups(username)
	if err != nil {
		return nil, 0, err
	}
	args := []interface{}{boundary, username, username, username, username}
	groupFilter := "0"
	if len(groups) > 0 {
		placeholders := make([]string, len(groups))
		for i, group := range groups {
			placeholders[i] = "?"
			args = append(args, group.GID)
		}
		groupFilter = "(chat_type='group' AND gid IN (" + strings.Join(placeholders, ",") + "))"
	}
	rows, err := DB.Query(`SELECT id, chat_type, from_user, to_user, gid, message, timestamp
		FROM messages WHERE id<=? AND (
		(chat_type='private' AND (from_user=? OR to_user=?) AND
		 EXISTS (SELECT 1 FROM friends WHERE user=? AND
		 friend=CASE WHEN from_user=? THEN to_user ELSE from_user END)) OR `+groupFilter+`)
		ORDER BY id ASC`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var history []models.Message
	for rows.Next() {
		var message models.Message
		var toUser, gid sql.NullString
		if err := rows.Scan(&message.ID, &message.ChatType, &message.FromUser, &toUser, &gid,
			&message.Content, &message.Timestamp); err != nil {
			return nil, 0, err
		}
		message.ToUser, message.GID = toUser.String, gid.String
		history = append(history, message)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return history, boundary, nil
}
