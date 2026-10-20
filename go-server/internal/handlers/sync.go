package handlers

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"fmt"
	"math"
	"net"
	"unicode/utf8"
)

// JSON numbers share the exact integer range of Python and JavaScript clients.
const maxSyncCursor = 9007199254740991

func syncCursor(value interface{}) (int64, bool) {
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number < 0 || number > maxSyncCursor || math.Trunc(number) != number {
		return 0, false
	}
	return int64(number), true
}

func handleSyncRequest(conn net.Conn, username string, key []byte, msg map[string]interface{}) {
	requestID, validID := msg["request_id"].(string)
	validID = validID && requestID != "" && utf8.RuneCountInString(requestID) <= 128
	sendError := func(text string) {
		reply := map[string]interface{}{"type": "sync_error", "error": text}
		if validID {
			reply["request_id"] = requestID
		}
		protocol.SendMsg(conn, reply)
	}
	after, validAfter := syncCursor(msg["after_id"])
	if !validID || !validAfter {
		sendError("消息同步参数错误")
		return
	}
	boundary, err := database.HistoryBoundary()
	if err != nil {
		sendError("消息同步失败，请重试")
		return
	}
	if raw, supplied := msg["boundary"]; supplied {
		requested, valid := syncCursor(raw)
		if !valid || requested > boundary {
			sendError("消息同步边界错误")
			return
		}
		boundary = requested
	}
	if after > boundary || boundary > maxSyncCursor {
		sendError("消息同步游标已失效，请重新登录")
		return
	}
	if err = sendSyncPage(conn, username, key, requestID, after, boundary); err != nil {
		sendError("消息同步失败，请重试")
	}
}

func sendSyncPage(conn net.Conn, username string, key []byte, requestID string, after, boundary int64) error {
	// Read and decrypt the complete page before announcing its start. A failure
	// never advances the client's persisted cursor or acknowledges a partial page.
	messages, more, err := database.GetSyncPage(username, boundary, after)
	if err != nil {
		return err
	}
	if err = protocol.SendMsgWait(conn, map[string]interface{}{"type": "sync_begin", "request_id": requestID, "after_id": after, "boundary": boundary}); err != nil {
		return err
	}
	for _, message := range messages {
		content, err := crypto.EncryptMessage(message.Content, key)
		if err != nil {
			return err
		}
		target := message.ToUser
		if message.ChatType == "group" {
			target = message.GID
		}
		payload := historyChatPayload(message.ChatType+"_chat", message.FromUser, target, content, message.Timestamp, message.ID, true)
		if message.ChatType == "group" {
			err = sendAuthorizedGroupHistory(conn, username, message.GID, payload)
		} else {
			err = protocol.SendMsgWait(conn, payload)
		}
		if err != nil {
			return err
		}
	}
	next := boundary
	if more {
		if len(messages) == 0 {
			return fmt.Errorf("sync page did not advance")
		}
		next = messages[len(messages)-1].ID
	}
	return protocol.SendMsgWait(conn, map[string]interface{}{"type": "sync_end", "request_id": requestID, "after_id": after, "boundary": boundary, "next_after_id": next, "has_more": more})
}
