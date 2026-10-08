package server

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"net"
)

func sendHistory(conn net.Conn, username string, key []byte) error {
	if err := protocol.SendMsgWait(conn, map[string]interface{}{"type": "history_begin"}); err != nil {
		return err
	}
	history, boundary, err := database.GetChatHistorySnapshot(username)
	if err != nil {
		return err
	}
	for _, message := range history {
		content, err := crypto.EncryptMessage(message.Content, key)
		if err != nil {
			return err
		}
		payload := map[string]interface{}{"type": message.ChatType + "_chat", "from": message.FromUser,
			"content": content, "timestamp": message.Timestamp, "message_id": message.ID}
		if message.ChatType == "group" {
			payload["gid"] = message.GID
		} else {
			payload["to"] = message.ToUser
		}
		if err := protocol.SendMsgWait(conn, payload); err != nil {
			return err
		}
	}
	return protocol.SendMsgWait(conn, map[string]interface{}{"type": "history_end", "boundary": boundary})
}
