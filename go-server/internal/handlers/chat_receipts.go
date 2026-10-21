package handlers

import (
	"chatroom/internal/crypto"
	"chatroom/internal/models"
	"chatroom/internal/protocol"
	"net"
)

func sendChatResult(conn net.Conn, kind string, request map[string]interface{}, id int64, failure string) {
	result := map[string]interface{}{"type": kind + "_result", "request_id": request["request_id"], "success": failure == ""}
	if failure != "" {
		result["error"] = failure
	} else {
		result["message_id"] = id
	}
	protocol.SendMsg(conn, result)
}

// Stored E2EE is relayed without server-side content decryption or session-key
// encryption. Legacy records keep their original transport-only path.
func storedChatPayload(message models.Message, key []byte, sync bool) (map[string]interface{}, error) {
	target := message.ToUser
	if message.ChatType == "group" {
		target = message.GID
	}
	if message.E2EE {
		envelope, err := parseStoredE2EE(message.Content)
		if err != nil {
			return nil, err
		}
		payload := e2eeChatPayload(message.ChatType, message.FromUser, target, envelope, message.Timestamp, message.ID)
		payload["history"] = true
		if sync {
			payload["sync"] = true
		}
		return payload, protocol.ValidateMessage(payload)
	}
	content, err := crypto.EncryptMessage(message.Content, key)
	if err != nil {
		return nil, err
	}
	return historyChatPayload(message.ChatType+"_chat", message.FromUser, target, content, message.Timestamp, message.ID, sync), nil
}

func chatPayload(kind, from, target, content, timestamp string, id int64) map[string]interface{} {
	payload := map[string]interface{}{"type": kind, "from": from, "content": content, "timestamp": timestamp, "message_id": id, "history": false, "encryption": "legacy"}
	if kind == "group_chat" {
		payload["gid"] = target
	} else {
		payload["to"] = target
	}
	return payload
}

// New messages must remain replayable with the extra metadata used by history
// and reconnect synchronization, even when the assigned ID later grows.
func validateReplayableChat(payload map[string]interface{}) error {
	replay := make(map[string]interface{}, len(payload)+2)
	for name, value := range payload {
		replay[name] = value
	}
	replay["history"], replay["sync"] = true, true
	return protocol.ValidateMessage(replay)
}

func historyChatPayload(kind, from, target, content, timestamp string, id int64, sync bool) map[string]interface{} {
	payload := chatPayload(kind, from, target, content, timestamp, id)
	payload["history"] = true
	if sync {
		payload["sync"] = true
	}
	// Older releases could store a frame with no room for new optional flags.
	// Keep its body and message ID intact; clients also track replay boundaries.
	if protocol.ValidateMessage(payload) != nil {
		delete(payload, "encryption")
		delete(payload, "sync")
		if protocol.ValidateMessage(payload) != nil {
			delete(payload, "history")
		}
	}
	return payload
}
