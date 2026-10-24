package handlers

import (
	"chatroom/internal/database"
	"chatroom/internal/models"
	"chatroom/internal/protocol"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"net"
	"time"
)

// SendHistory rechecks membership and enqueues under the same group operation
// lock used by kick/leave/disband. History packets cannot be queued after removal.
func SendHistory(conn net.Conn, username string, key []byte, kind, target string, before int64) error {
	boundary, err := database.HistoryBoundary()
	if err != nil {
		return err
	}
	if err = protocol.SendMsgWait(conn, map[string]interface{}{"type": "history_begin"}); err != nil {
		return err
	}
	history, more, err := database.GetHistoryPage(username, boundary, before, kind, target)
	if err != nil {
		return err
	}
	for _, message := range history {
		payload, err := storedChatPayload(message, key, false)
		if err != nil {
			return err
		}
		if message.ChatType == "group" {
			err = sendAuthorizedGroupHistory(conn, username, message.GID, payload)
		} else {
			err = protocol.SendMsgWait(conn, payload)
		}
		if err != nil {
			return err
		}
	}
	end := map[string]interface{}{"type": "history_end", "boundary": boundary}
	if kind != "" {
		cursor := before
		if len(history) > 0 {
			cursor = history[0].ID
		}
		end["history_kind"], end["history_target"], end["has_more"], end["before_id"] = kind, target, more, cursor
	} else if more {
		end["has_more"] = true
	}
	return protocol.SendMsgWait(conn, end)
}

func sendHistoryError(conn net.Conn, kind, target, message string) {
	payload := map[string]interface{}{"type": "history_error", "error": message}
	if (kind == "private" || kind == "group") && target != "" {
		payload["history_kind"], payload["history_target"] = kind, target
	}
	protocol.SendMsg(conn, payload)
}

func handleHistoryRequest(conn net.Conn, username string, key []byte, msg map[string]interface{}) {
	kind, ok := msg["chat_type"].(string)
	target, valid := msg["target"].(string)
	value, number := msg["before_id"].(float64)
	if !ok || !valid || !number || target == "" || (kind != "group" && kind != "private") || value <= 0 || value > float64(math.MaxInt64) || math.Trunc(value) != value {
		sendHistoryError(conn, kind, target, "历史查询参数错误")
		return
	}
	before := int64(math.MaxInt64)
	if value < float64(math.MaxInt64) {
		before = int64(value)
	}
	allowed := false
	if kind == "private" {
		allowed, _ = database.AreFriends(username, target)
	} else {
		group, err := database.GetGroup(target)
		if err == nil {
			for _, name := range group.Members {
				if name == username {
					allowed = true
					break
				}
			}
		}
	}
	if !allowed {
		sendHistoryError(conn, kind, target, "无权读取该会话历史")
		return
	}
	if err := SendHistory(conn, username, key, kind, target, before); err != nil {
		sendHistoryError(conn, kind, target, "历史加载失败，请重试")
	}
}

// Publish the login snapshot atomically with respect to group notifications.
// Large snapshots use the same chunk format as the Python server.
func SendUserGroups(conn net.Conn, username string) error {
	groupCatalogMu.Lock()
	defer groupCatalogMu.Unlock()
	groups, err := database.GetUserGroups(username)
	if err != nil {
		return err
	}
	if groups == nil {
		groups = make([]models.Group, 0)
	}
	payload := map[string]interface{}{"type": "user_groups_list", "groups": groups}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(data) <= protocol.MaxMessageLen {
		return protocol.SendMsg(conn, payload)
	}
	size := (protocol.MaxMessageLen - 256) / 2
	for start := 0; start < len(data); {
		end := start + size
		if end > len(data) {
			end = len(data)
		}
		for end < len(data) && data[end]&0xc0 == 0x80 {
			end--
		}
		if err = protocol.SendMsg(conn, map[string]interface{}{"type": "user_groups_chunk", "data": string(data[start:end]), "first": start == 0, "last": end == len(data)}); err != nil {
			return err
		}
		start = end
	}
	return nil
}

func sendAuthorizedGroupHistory(conn net.Conn, username, gid string, payload map[string]interface{}) error {
	deadline := time.Now().Add(protocol.WriteTimeout)
	for {
		unlock := LockGroup(gid)
		group, err := database.GetGroup(gid)
		member := false
		if err == nil {
			for _, name := range group.Members {
				if name == username {
					member = true
					break
				}
			}
		}
		if member {
			err = protocol.TrySendMsg(conn, payload)
		}
		unlock()
		if errors.Is(err, sql.ErrNoRows) || err == nil {
			return nil
		}
		if !errors.Is(err, protocol.ErrQueueFull) {
			return err
		}
		if !time.Now().Before(deadline) {
			conn.Close()
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
}
