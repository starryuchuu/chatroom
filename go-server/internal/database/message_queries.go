package database

import (
	"chatroom/internal/models"
	"database/sql"
	"strings"
)

const HistoryPageSize = 100

func SaveMessage(chatType, fromUser, toUser, gid, message, timestamp string) error {
	_, err := SaveMessageWithID(chatType, fromUser, toUser, gid, message, timestamp)
	return err
}
func SaveMessageWithID(chatType, fromUser, toUser, gid, message, timestamp string) (int64, error) {
	result, err := DB.Exec(`INSERT INTO messages(chat_type,from_user,to_user,gid,message,timestamp) VALUES(?,?,?,?,?,?)`, chatType, fromUser, toUser, gid, message, timestamp)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}
func HistoryBoundary() (int64, error) {
	var boundary int64
	err := DB.QueryRow("SELECT COALESCE(MAX(id),0) FROM messages").Scan(&boundary)
	return boundary, err
}
func GetChatHistory(username string) ([]models.Message, error) {
	history, _, err := GetChatHistorySnapshot(username)
	return history, err
}

// GetChatHistorySnapshot returns the newest bounded page under one ID boundary.
func GetChatHistorySnapshot(username string) ([]models.Message, int64, error) {
	boundary, err := HistoryBoundary()
	if err != nil {
		return nil, 0, err
	}
	history, _, err := GetHistoryPage(username, boundary, 0, "", "")
	return history, boundary, err
}

// GetHistoryPage uses an exclusive before-ID cursor; OFFSET is never used.
func GetHistoryPage(username string, boundary, before int64, kind, target string) ([]models.Message, bool, error) {
	groups, err := GetUserGroups(username)
	if err != nil {
		return nil, false, err
	}
	condition := "id<=?"
	args := []interface{}{boundary}
	if before > 0 {
		condition += " AND id<?"
		args = append(args, before)
	}
	private := "0"
	if kind != "group" {
		private = `(chat_type='private' AND (from_user=? OR to_user=?) AND EXISTS (SELECT 1 FROM friends WHERE user=? AND friend=CASE WHEN from_user=? THEN to_user ELSE from_user END))`
		args = append(args, username, username, username, username)
		if kind == "private" {
			private += " AND (from_user=? OR to_user=?)"
			args = append(args, target, target)
		}
	}
	var gids []string
	if kind != "private" {
		for _, g := range groups {
			if kind == "" || g.GID == target {
				gids = append(gids, g.GID)
			}
		}
	}
	group := "0"
	if len(gids) > 0 {
		placeholders := make([]string, len(gids))
		for i, gid := range gids {
			placeholders[i] = "?"
			args = append(args, gid)
		}
		group = "(chat_type='group' AND gid IN (" + strings.Join(placeholders, ",") + "))"
	}
	args = append(args, HistoryPageSize+1)
	rows, err := DB.Query(`SELECT id,chat_type,from_user,to_user,gid,message,timestamp FROM messages WHERE `+condition+` AND ((`+private+`) OR `+group+`) ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var history []models.Message
	for rows.Next() {
		var m models.Message
		var to, gid sql.NullString
		if err = rows.Scan(&m.ID, &m.ChatType, &m.FromUser, &to, &gid, &m.Content, &m.Timestamp); err != nil {
			return nil, false, err
		}
		m.ToUser, m.GID = to.String, gid.String
		history = append(history, m)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(history) > HistoryPageSize
	if more {
		history = history[:HistoryPageSize]
	}
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}
	return history, more, nil
}
