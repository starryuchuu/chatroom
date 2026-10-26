package handlers

import (
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"errors"
	"net"
	"unicode/utf8"
)

func saveChatMessage(request map[string]interface{}, kind, sender, recipient, gid, body, at string, encrypted bool) (database.ChatSave, error) {
	key := ""
	if value, present := request["idempotency_key"]; present {
		var ok bool
		key, ok = value.(string)
		if !ok || !database.ValidReceiptKey(key) {
			return database.ChatSave{}, errors.New("invalid send receipt key")
		}
	}
	return database.SaveChatWithReceipt(kind, sender, recipient, gid, body, at, encrypted, key)
}

func handleMessageStatus(conn net.Conn, username string, request map[string]interface{}) {
	key, _ := request["idempotency_key"].(string)
	kind, _ := request["chat_type"].(string)
	target, _ := request["target"].(string)
	reply := map[string]interface{}{"type": "message_status_result", "request_id": request["request_id"],
		"idempotency_key": request["idempotency_key"], "chat_type": kind, "target": target, "success": false}
	if !database.ValidReceiptKey(key) || (kind != "private" && kind != "group") || target == "" || !utf8.ValidString(target) || utf8.RuneCountInString(target) > 256 {
		reply["error"] = "消息查询参数错误"
	} else {
		saved, err := database.LookupSendReceipt(username, key, kind, target)
		if err != nil {
			reply["error"] = "暂时无法核对发送结果，请稍后重试"
		} else {
			reply["success"], reply["status"] = true, "not_found"
			if saved.ID != 0 {
				reply["status"], reply["message_id"], reply["timestamp"] = "saved", saved.ID, saved.Timestamp
			}
		}
	}
	protocol.SendMsg(conn, reply)
}
