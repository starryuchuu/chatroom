package database

import (
	"chatroom/internal/models"
	"database/sql"
	"strconv"
	"strings"
)

const HistoryPageSize = 100

func SaveMessage(chatType, fromUser, toUser, gid, message, timestamp string) error {
	_, err := SaveMessageWithID(chatType, fromUser, toUser, gid, message, timestamp)
	return err
}
func SaveMessageWithID(chatType, fromUser, toUser, gid, message, timestamp string) (int64, error) {
	tx, err := DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	fromUser, err = storage.putName(tx, fromUser)
	if err != nil {
		return 0, err
	}
	if toUser != "" {
		toUser, err = storage.putName(tx, toUser)
		if err != nil {
			return 0, err
		}
	}
	result, err := tx.Exec(`INSERT INTO messages(chat_type,from_user,to_user,gid,message,timestamp) VALUES(?,?,?,?,?,?)`, chatType, fromUser, toUser, gid, "", "")
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	body, err := storage.seal(message, messageStorageContext(id, chatType, fromUser, toUser, gid)...)
	if err != nil {
		return 0, err
	}
	at, err := storage.seal(timestamp, "messages", "timestamp", strconv.FormatInt(id, 10))
	if err != nil {
		return 0, err
	}
	if _, err = tx.Exec("UPDATE messages SET message=?,timestamp=? WHERE id=?", body, at, id); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
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
	return getAuthorizedMessagePage(username, boundary, before, kind, target, false)
}

// GetSyncPage walks all currently authorized conversations forwards inside one
// fixed snapshot. Reconnecting clients can recover a gap larger than one page.
func GetSyncPage(username string, boundary, after int64) ([]models.Message, bool, error) {
	return getAuthorizedMessagePage(username, boundary, after, "", "", true)
}

func getAuthorizedMessagePage(username string, boundary, cursor int64, kind, target string, forward bool) ([]models.Message, bool, error) {
	groups, err := GetUserGroups(username)
	if err != nil {
		return nil, false, err
	}
	condition := "id<=?"
	args := []interface{}{boundary}
	if forward {
		condition += " AND id>?"
		args = append(args, cursor)
	} else if cursor > 0 {
		condition += " AND id<?"
		args = append(args, cursor)
	}
	private := "0"
	if kind != "group" {
		private = `(chat_type='private' AND (from_user=? OR to_user=?) AND EXISTS (SELECT 1 FROM friends WHERE user=? AND friend=CASE WHEN from_user=? THEN to_user ELSE from_user END))`
		token := storage.token(username)
		args = append(args, token, token, token, token)
		if kind == "private" {
			private += " AND (from_user=? OR to_user=?)"
			args = append(args, storage.token(target), storage.token(target))
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
	order := "DESC"
	if forward {
		order = "ASC"
	}
	rows, err := DB.Query(`SELECT id,chat_type,from_user,to_user,gid,message,timestamp FROM messages WHERE `+condition+` AND ((`+private+`) OR `+group+`) ORDER BY id `+order+` LIMIT ?`, args...)
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
	rows.Close()
	for i := range history {
		m := &history[i]
		m.Content, err = storage.open(m.Content, messageStorageContext(m.ID, m.ChatType, m.FromUser, m.ToUser, m.GID)...)
		if err != nil {
			return nil, false, err
		}
		m.Timestamp, err = storage.open(m.Timestamp, "messages", "timestamp", strconv.FormatInt(m.ID, 10))
		if err != nil {
			return nil, false, err
		}
		m.FromUser, err = storage.name(m.FromUser)
		if err != nil {
			return nil, false, err
		}
		m.ToUser, err = storage.name(m.ToUser)
		if err != nil {
			return nil, false, err
		}
	}
	if !forward {
		for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
			history[i], history[j] = history[j], history[i]
		}
	}
	return history, more, nil
}
