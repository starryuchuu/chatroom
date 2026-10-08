package handlers

import (
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

func chatPayload(kind, from, target, content, timestamp string, id int64) map[string]interface{} {
	payload := map[string]interface{}{"type": kind, "from": from, "content": content, "timestamp": timestamp, "message_id": id}
	if kind == "group_chat" {
		payload["gid"] = target
	} else {
		payload["to"] = target
	}
	return payload
}
