package handlers

import (
	"chatroom/internal/database"
	"chatroom/internal/e2ee"
	"chatroom/internal/protocol"
	"chatroom/internal/types"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"sync"
	"time"
	"unicode/utf8"
)

// Enrollment cannot race a legacy send's downgrade check and persistence.
// Group sends additionally hold their existing group operation lock.
var e2eeIdentityMu sync.RWMutex

func e2eeRequestID(request map[string]interface{}) (string, bool) {
	id, valid := request["request_id"].(string)
	return id, valid && id != "" && utf8.RuneCountInString(id) <= 128
}

func handleE2EEIdentityPublish(conn net.Conn, username string, request map[string]interface{}) {
	id, validID := e2eeRequestID(request)
	reply := map[string]interface{}{"type": "e2ee_identity_result", "success": false}
	if validID {
		reply["request_id"] = id
	}
	fail := func(text string) {
		reply["error"] = text
		protocol.SendMsg(conn, reply)
	}
	if !validID {
		fail("加密身份请求参数错误")
		return
	}
	bundle, err := e2ee.Bundle(request["identity"])
	if err != nil || e2ee.VerifyPublication(username, bundle, request["proof"]) != nil {
		fail("加密身份或密钥证明无效")
		return
	}
	serialized, err := e2ee.Canonical(bundle)
	if err != nil {
		fail("加密身份格式错误")
		return
	}
	e2eeIdentityMu.Lock()
	stored, err := database.PublishE2EEIdentity(username, string(serialized))
	e2eeIdentityMu.Unlock()
	if stored != "" {
		if identity, parseErr := e2ee.ParseBundle(stored); parseErr == nil {
			reply["identity"] = identity
		}
	}
	if err != nil {
		if stored != "" {
			fail("此账号已有加密身份；请导入原有密钥备份，不能覆盖身份")
		} else {
			fail("加密身份保存失败，请稍后重试")
		}
		return
	}
	reply["success"] = true
	protocol.SendMsg(conn, reply)
}

func loadE2EEIdentities(members []string) (map[string]map[string]interface{}, []string, error) {
	identities := make(map[string]map[string]interface{}, len(members))
	missing := make([]string, 0)
	for _, name := range members {
		stored, err := database.GetE2EEIdentity(name)
		if err != nil {
			return nil, nil, err
		}
		if stored == "" {
			missing = append(missing, name)
			continue
		}
		identity, err := e2ee.ParseBundle(stored)
		if err != nil {
			return nil, nil, err
		}
		identities[name] = identity
	}
	sort.Strings(missing)
	return identities, missing, nil
}

func handleE2EEKeysRequest(conn net.Conn, username string, request map[string]interface{}) {
	id, validID := e2eeRequestID(request)
	kind, validKind := request["kind"].(string)
	target, validTarget := request["target"].(string)
	validTarget = validTarget && target != "" && utf8.ValidString(target) && utf8.RuneCountInString(target) <= 256
	reply := map[string]interface{}{"type": "e2ee_keys", "success": false}
	if validID {
		reply["request_id"] = id
	}
	if validKind {
		reply["kind"] = kind
	}
	if validTarget {
		reply["target"] = target
	}
	fail := func(text string) {
		reply["error"] = text
		protocol.SendMsg(conn, reply)
	}
	if !validID || !validKind || !validTarget || target == "" || (kind != "private" && kind != "group") {
		fail("加密收件人请求参数错误")
		return
	}
	e2eeIdentityMu.RLock()
	defer e2eeIdentityMu.RUnlock()
	var members []string
	if kind == "private" {
		friends, err := database.AreFriends(username, target)
		if err != nil || !friends || target == username {
			fail("无权读取该会话加密身份")
			return
		}
		members = []string{username, target}
	} else {
		unlock := LockGroup(target)
		defer unlock()
		group, err := database.GetGroup(target)
		if err != nil {
			fail("群组不存在")
			return
		}
		member := false
		for _, name := range group.Members {
			if name == username {
				member = true
			}
		}
		if !member {
			fail("无权读取该会话加密身份")
			return
		}
		members = uniqueGroupMembers(group.Members)
	}
	sort.Strings(members)
	if len(members) == 0 || len(members) > e2ee.MaxRecipients {
		fail("端到端加密最多支持 256 名会话成员")
		return
	}
	identities, missing, err := loadE2EEIdentities(members)
	if err != nil {
		fail("无法读取加密身份，请稍后重试")
		return
	}
	reply["success"], reply["members"], reply["identities"], reply["missing"] = true, members, identities, missing
	if err := protocol.ValidateMessage(reply); err != nil {
		fail("加密身份列表超过报文限制")
		return
	}
	protocol.SendMsg(conn, reply)
}

func requiresE2EE(members []string) (bool, error) {
	for _, member := range members {
		identity, err := database.GetE2EEIdentity(member)
		if err != nil {
			return false, err
		}
		if identity != "" {
			return true, nil
		}
	}
	return false, nil
}

func e2eeChatPayload(kind, sender, target string, envelope map[string]interface{}, timestamp string, id int64) map[string]interface{} {
	payload := map[string]interface{}{"type": kind + "_chat", "from": sender, "e2ee": envelope,
		"timestamp": timestamp, "message_id": id, "history": false, "encryption": "e2ee_v1"}
	if kind == "group" {
		payload["gid"] = target
	} else {
		payload["to"] = target
	}
	return payload
}

// handleE2EEChat requires the enrollment read lock and, for groups, their
// operation lock. A changed membership/key set is rejected before persistence.
func handleE2EEChat(conn net.Conn, sender, kind, target string, members []string, request map[string]interface{}, manager types.ClientManager) {
	members = uniqueGroupMembers(members)
	fail := func(text string) { sendChatResult(conn, kind+"_chat", request, 0, text) }
	if _, mixed := request["content"]; mixed {
		fail("加密消息不能同时包含旧版消息正文")
		return
	}
	if len(members) == 0 || len(members) > e2ee.MaxRecipients {
		fail("端到端加密最多支持 256 名会话成员")
		return
	}
	identities, missing, err := loadE2EEIdentities(members)
	if err != nil || len(missing) != 0 {
		fail("所有会话成员必须先设置端到端加密身份")
		return
	}
	envelope, err := e2ee.ValidateEnvelope(request["e2ee"], sender, kind, target, identities)
	if err != nil {
		fail("加密消息校验失败；收件人或身份可能已变化，请刷新后重试")
		return
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	if err := validateReplayableChat(e2eeChatPayload(kind, sender, target, envelope, timestamp, 9223372036854775807)); err != nil {
		fail("加密消息内容过长")
		return
	}
	serialized, err := json.Marshal(envelope)
	if err != nil {
		fail("加密消息格式错误")
		return
	}
	to, gid := target, ""
	if kind == "group" {
		to, gid = "", target
	}
	id, err := database.SaveE2EEMessageWithID(kind, sender, to, gid, string(serialized), timestamp)
	if err != nil {
		fail("加密消息保存失败，请重试")
		return
	}
	sendChatResult(conn, kind+"_chat", request, id, "")
	payload := e2eeChatPayload(kind, sender, target, envelope, timestamp, id)
	for _, member := range members {
		if member == sender {
			protocol.SendMsg(conn, payload)
		} else if recipient, found := manager.GetClient(member); found {
			protocol.SendMsg(recipient.Conn, payload)
		}
	}
}

func parseStoredE2EE(serialized string) (map[string]interface{}, error) {
	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(serialized), &envelope); err != nil || envelope == nil {
		return nil, errors.New("invalid stored E2EE envelope")
	}
	return envelope, nil
}
