package handlers

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"log"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"chatroom/internal/types" // 导入 types 包以访问 ClientManager 接口
)

const groupNameMaxLen = 128

func validGroupName(name string) bool {
	return strings.TrimSpace(name) != "" && utf8.RuneCountInString(name) <= groupNameMaxLen
}

func groupNameForNotification(name string) string {
	count := 0
	for index := range name {
		if count == groupNameMaxLen {
			return name[:index]
		}
		count++
	}
	return name
}

// 待处理的好友请求：{requester: set(target)}，仅真实收到请求者可响应，防止伪造好友关系
var (
	pendingFriendRequests   = make(map[string]map[string]time.Time)
	pendingFriendRequestsMu sync.Mutex
)

// 待加入群组的用户：{gid: set(username)}，仅收到过邀请的用户可加入，防止越权加入
var (
	pendingGroupJoins   = make(map[string]map[string]groupInvitation)
	pendingGroupJoinsMu sync.Mutex
)

// HandleClientMessages 处理认证成功后的客户端消息循环
func HandleClientMessages(conn net.Conn, username string, sessionKey []byte, clientManager types.ClientManager) {
	for {
		// 重置读取超时
		conn.SetReadDeadline(time.Now().Add(30 * time.Minute))
		msg, err := protocol.RecvMsg(conn)
		if err != nil {
			log.Printf("event=client_messages_failed error_type=%T", err)
			break // 退出循环，连接将在上层关闭
		}

		msgType, ok := msg["type"].(string)
		if !ok {
			log.Printf("event=invalid_message_type")
			continue
		}

		log.Printf("event=client_messages_received")

		switch msgType {
		case "history_request":
			handleHistoryRequest(conn, username, sessionKey, msg)
		case "sync_request":
			handleSyncRequest(conn, username, sessionKey, msg)
		case "e2ee_identity_publish":
			handleE2EEIdentityPublish(conn, username, msg)
		case "e2ee_keys_request":
			handleE2EEKeysRequest(conn, username, msg)
		case "private_chat":
			handlePrivateChat(conn, username, sessionKey, msg, clientManager)
		case "friend_request":
			handleFriendRequest(conn, username, msg, clientManager)
		case "friend_response":
			handleFriendResponse(conn, username, msg, clientManager)
		case "group_chat":
			handleGroupChat(conn, username, sessionKey, msg, clientManager)
		case "group_create":
			handleGroupCreate(conn, username, msg, clientManager)
		case "group_invite":
			handleGroupInvite(conn, username, msg, clientManager)
		case "group_invite_response":
			handleGroupInviteResponse(conn, username, msg)
		case "group_join":
			handleGroupJoin(conn, username, msg, clientManager)
		case "group_leave":
			handleGroupLeave(conn, username, msg, clientManager)
		case "group_kick":
			handleGroupKick(conn, username, msg, clientManager)
		case "group_info":
			handleGroupInfo(conn, username, msg)
		case "group_disband":
			handleGroupDisband(conn, username, msg, clientManager)
		case "group_transfer":
			handleGroupTransfer(conn, username, msg, clientManager)
		case "group_rename":
			handleGroupRename(conn, username, msg, clientManager)
		default:
			log.Printf("event=unknown_message_type")
		}
	}
}

func handleGroupInvite(conn net.Conn, inviter string, msg map[string]interface{}, clientManager types.ClientManager) {
	unlock := lockGroupOperation(msg)
	defer unlock()
	toUser, ok := msg["to"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "目标用户格式错误"})
		return
	}
	gid, ok := msg["gid"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "群组ID格式错误"})
		return
	}

	log.Printf("event=group_invite_received")

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("event=group_invite_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "群组不存在"})
		return
	}

	// 检查邀请者是否是群组成员
	isMember := false
	for _, member := range group.Members {
		if member == inviter {
			isMember = true
			break
		}
	}
	if !isMember {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "您不是该群成员，无法邀请"})
		log.Printf("event=group_invite_failed")
		return
	}

	// 检查被邀请者是否已经是群组成员
	isAlreadyMember := false
	for _, member := range group.Members {
		if member == toUser {
			isAlreadyMember = true
			break
		}
	}
	if isAlreadyMember {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "用户 " + toUser + " 已是群成员"})
		log.Printf("event=group_invite_failed")
		return
	}
	if len(uniqueGroupMembers(group.Members)) >= maxGroupMembers {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": groupCapacityError})
		return
	}

	// 检查被邀请用户是否存在
	exists, err := database.UserExists(toUser)
	if err != nil {
		log.Printf("event=group_invite_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "服务器内部错误"})
		return
	}
	if !exists {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "用户 " + toUser + " 不存在"})
		log.Printf("event=group_invite_failed")
		return
	}

	// 检查是否是好友关系（直接查询数据库而不是依赖在线客户端信息）
	areFriends, err := database.AreFriends(inviter, toUser)
	if err != nil {
		log.Printf("event=group_invite_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "服务器内部错误"})
		return
	}
	if !areFriends {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "您和 " + toUser + " 不是好友关系"})
		log.Printf("event=group_invite_failed")
		return
	}

	// 记录待加入请求（仅收到过邀请的用户才能 join，防止越权加入）
	pendingGroupJoinsMu.Lock()
	pruneGroupInvitesLocked(time.Now())
	if pendingGroupJoins[gid] == nil {
		pendingGroupJoins[gid] = make(map[string]groupInvitation)
	}
	created := time.Now()
	if err := database.SavePendingInvite(gid, toUser, inviter, created); err != nil {
		pendingGroupJoinsMu.Unlock()
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "邀请保存失败，请重试"})
		return
	}
	pendingGroupJoins[gid][toUser] = groupInvitation{Inviter: inviter, CreatedAt: created}
	pendingGroupJoinsMu.Unlock()

	// 转发邀请给被邀请用户
	toClient, found := clientManager.GetClient(toUser)
	if found {
		err := protocol.SendMsg(toClient.Conn, map[string]interface{}{
			"type":       "group_invite",
			"from":       inviter,
			"gid":        gid,
			"group_name": group.GroupName,
		})
		if err != nil {
			log.Printf("event=group_invite_failed error_type=%T", err)
			protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": true, "message": "邀请已保存，对方重新登录后可见"})
			return
		}
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": true, "message": "已向 " + toUser + " 发送邀请"})
		log.Printf("event=group_invite_received")
	} else {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": true, "message": "邀请已保存，对方上线后可见"})
		log.Printf("event=group_invite_failed")
	}
}

func handleGroupJoin(conn net.Conn, userToJoin string, msg map[string]interface{}, clientManager types.ClientManager) {
	unlock := lockGroupOperation(msg)
	joined := false
	defer func() {
		unlock()
		if joined {
			if client, found := clientManager.GetClient(userToJoin); found && len(client.SessionKey) > 0 {
				gid, _ := msg["gid"].(string)
				if err := SendHistory(conn, userToJoin, client.SessionKey, "group", gid, 0); err != nil {
					sendHistoryError(conn, "group", gid, "入群历史加载失败，请重试")
				}
			}
		}
	}()
	gid, ok := msg["gid"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_join_result", "success": false, "error": "群组ID格式错误"})
		return
	}

	log.Printf("event=group_join_received")

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("event=group_join_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_join_result", "success": false, "error": "群组不存在"})
		return
	}

	// 检查用户是否已经是群组成员
	isAlreadyMember := false
	for _, member := range group.Members {
		if member == userToJoin {
			isAlreadyMember = true
			break
		}
	}
	if isAlreadyMember {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_join_result", "success": false, "error": "您已是该群成员"})
		log.Printf("event=group_join_failed")
		return
	}
	// The invitation may have been issued while the group had room. Recheck
	// under the same operation lock immediately before the membership write.
	if len(uniqueGroupMembers(group.Members)) >= maxGroupMembers {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_join_result", "success": false, "error": groupCapacityError})
		return
	}

	// 防越权校验：仅收到过邀请的用户可加入群组
	pendingGroupJoinsMu.Lock()
	pruneGroupInvitesLocked(time.Now())
	invited := pendingGroupJoins[gid] != nil
	if invited {
		_, invited = pendingGroupJoins[gid][userToJoin]
	}
	if !invited {
		pendingGroupJoinsMu.Unlock()
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_join_result", "success": false, "error": "您未被邀请加入该群组"})
		log.Printf("event=group_join_denied")
		return
	}
	pendingGroupJoinsMu.Unlock()

	// 添加用户到群组成员列表
	group.Members = append(group.Members, userToJoin)

	// 更新数据库中的群组成员
	err = database.UpdateGroupMembersAndConsumeInvite(gid, group.Members, userToJoin)
	if err != nil {
		log.Printf("event=group_join_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_join_result", "success": false, "error": "加入失败"})
		return
	}
	pendingGroupJoinsMu.Lock()
	delete(pendingGroupJoins[gid], userToJoin)
	if len(pendingGroupJoins[gid]) == 0 {
		delete(pendingGroupJoins, gid)
	}
	pendingGroupJoinsMu.Unlock()

	// 发送成功响应给加入者
	payload := map[string]interface{}{
		"type":       "group_join_result",
		"success":    true,
		"gid":        gid,
		"group_name": group.GroupName,
		"owner":      group.Owner,
		"members":    group.Members,
	}

	protocol.SendMsg(conn, payload)
	joined = true
	log.Printf("event=group_join_completed")

	// 向所有成员广播群组更新信息
	updatePayload := map[string]interface{}{
		"type":       "group_update",
		"gid":        gid,
		"group_name": group.GroupName,
		"owner":      group.Owner,
		"members":    group.Members,
	}

	for _, member := range group.Members {
		if client, found := clientManager.GetClient(member); found {
			protocol.SendMsg(client.Conn, updatePayload)
		}
	}
}

func handleGroupLeave(conn net.Conn, userToLeave string, msg map[string]interface{}, clientManager types.ClientManager) {
	unlock := lockGroupOperation(msg)
	defer unlock()
	gid, ok := msg["gid"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_leave_result", "success": false, "error": "群组ID格式错误"})
		return
	}

	log.Printf("event=group_leave_received")

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("event=group_leave_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_leave_result", "success": false, "error": "群组不存在"})
		return
	}

	// 检查用户是否是群组成员
	isMember := false
	for _, member := range group.Members {
		if member == userToLeave {
			isMember = true
			break
		}
	}
	if !isMember {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_leave_result", "success": false, "error": "您不是该群成员"})
		log.Printf("event=group_leave_failed")
		return
	}

	// 检查用户是否是群主
	if userToLeave == group.Owner {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_leave_result", "success": false, "error": "群主不能直接退出群聊，请先解散群聊或转让群主"})
		log.Printf("event=group_leave_failed")
		return
	}

	// 从群组成员列表中移除用户
	newMembers := []string{}
	for _, member := range group.Members {
		if member != userToLeave {
			newMembers = append(newMembers, member)
		}
	}
	group.Members = newMembers

	// 更新数据库中的群组成员
	err = database.UpdateGroupMembers(gid, group.Members)
	if err != nil {
		log.Printf("event=group_leave_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_leave_result", "success": false, "error": "退出失败"})
		return
	}

	// 发送成功响应给离开者
	protocol.SendMsg(conn, map[string]interface{}{
		"type":    "group_leave_result",
		"success": true,
		"gid":     gid,
	})
	log.Printf("event=group_leave_completed")

	// 向所有剩余成员广播群组更新信息
	updatePayload := map[string]interface{}{
		"type":       "group_update",
		"gid":        gid,
		"group_name": group.GroupName,
		"owner":      group.Owner,
		"members":    group.Members,
	}

	for _, member := range group.Members {
		if client, found := clientManager.GetClient(member); found {
			protocol.SendMsg(client.Conn, updatePayload)
		}
	}
}

func handleGroupKick(conn net.Conn, requester string, msg map[string]interface{}, clientManager types.ClientManager) {
	unlock := lockGroupOperation(msg)
	defer unlock()
	gid, ok := msg["gid"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_kick_result", "success": false, "error": "群组ID格式错误"})
		return
	}
	kickUser, ok := msg["kick"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_kick_result", "success": false, "error": "被踢用户格式错误"})
		return
	}

	log.Printf("event=group_kick_received")

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("event=group_kick_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_kick_result", "success": false, "error": "群组不存在"})
		return
	}

	// 检查请求者是否是群主
	if requester != group.Owner {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_kick_result", "success": false, "error": "只有群主才能踢人"})
		log.Printf("event=group_kick_failed")
		return
	}

	// 检查被踢用户是否是群组成员
	isMember := false
	for _, member := range group.Members {
		if member == kickUser {
			isMember = true
			break
		}
	}
	if !isMember {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_kick_result", "success": false, "error": "该用户不是群成员"})
		log.Printf("event=group_kick_failed")
		return
	}

	// 检查是否试图踢自己
	if kickUser == requester {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_kick_result", "success": false, "error": "不能踢自己"})
		log.Printf("event=group_kick_failed")
		return
	}

	// 从群组成员列表中移除被踢用户
	newMembers := []string{}
	for _, member := range group.Members {
		if member != kickUser {
			newMembers = append(newMembers, member)
		}
	}
	group.Members = newMembers

	// 更新数据库中的群组成员
	err = database.UpdateGroupMembers(gid, group.Members)
	if err != nil {
		log.Printf("event=group_kick_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_kick_result", "success": false, "error": "踢人失败"})
		return
	}

	// 通知被踢者
	if kickClient, found := clientManager.GetClient(kickUser); found {
		protocol.SendMsg(kickClient.Conn, map[string]interface{}{
			"type":       "group_kick_notification",
			"gid":        gid,
			"group_name": group.GroupName,
		})
	}

	// 向群主确认
	protocol.SendMsg(conn, map[string]interface{}{
		"type":    "group_kick_result",
		"success": true,
		"gid":     gid,
		"kick":    kickUser,
	})
	log.Printf("event=group_kick_completed")

	// 向所有剩余成员广播群组更新信息
	updatePayload := map[string]interface{}{
		"type":       "group_update",
		"gid":        gid,
		"group_name": group.GroupName,
		"owner":      group.Owner,
		"members":    group.Members,
	}

	for _, member := range group.Members {
		if client, found := clientManager.GetClient(member); found {
			protocol.SendMsg(client.Conn, updatePayload)
		}
	}
}

func handleGroupInfo(conn net.Conn, username string, msg map[string]interface{}) {
	unlock := lockGroupOperation(msg)
	defer unlock()
	gid, ok := msg["gid"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_info", "error": "群组ID格式错误"})
		return
	}

	log.Printf("event=group_info_received")

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("event=group_info_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_info", "gid": gid, "error": "群组不存在"})
		return
	}

	// 权限校验：仅群成员可查看群组信息（防止成员列表泄露）
	isMember := false
	for _, member := range group.Members {
		if member == username {
			isMember = true
			break
		}
	}
	if !isMember {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_info", "gid": gid, "error": "您不是该群成员，无法查看群组信息"})
		log.Printf("event=group_info_denied")
		return
	}

	// 构建响应消息
	response := map[string]interface{}{
		"type":       "group_info",
		"gid":        group.GID,
		"group_name": group.GroupName,
		"owner":      group.Owner,
		"members":    group.Members,
	}

	protocol.SendMsg(conn, response)
	log.Printf("event=group_info_completed")
}

func handleGroupDisband(conn net.Conn, requester string, msg map[string]interface{}, clientManager types.ClientManager) {
	unlock := lockGroupOperation(msg)
	defer unlock()
	gid, ok := msg["gid"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_disband_result", "success": false, "error": "群组ID格式错误"})
		return
	}

	log.Printf("event=group_disband_received")

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("event=group_disband_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_disband_result", "success": false, "error": "群组不存在"})
		return
	}

	// 检查请求者是否是群主
	if requester != group.Owner {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_disband_result", "success": false, "error": "只有群主才能解散群聊"})
		log.Printf("event=group_disband_failed")
		return
	}

	// 从数据库中删除群组
	err = database.DeleteGroup(gid)
	if err != nil {
		log.Printf("event=group_disband_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_disband_result", "success": false, "error": "解散群聊失败"})
		return
	}
	pendingGroupJoinsMu.Lock()
	delete(pendingGroupJoins, gid)
	pendingGroupJoinsMu.Unlock()

	// 通知所有成员群组已解散
	disbandNotification := map[string]interface{}{
		"type":       "group_disband_notification",
		"gid":        gid,
		"group_name": group.GroupName,
	}

	for _, member := range group.Members {
		if member == requester {
			continue
		}
		if client, found := clientManager.GetClient(member); found {
			protocol.SendMsg(client.Conn, disbandNotification)
		}
	}

	// 向请求者确认
	protocol.SendMsg(conn, map[string]interface{}{
		"type":    "group_disband_result",
		"success": true,
		"gid":     gid,
	})
	log.Printf("event=group_disband_completed")
}

func handleGroupTransfer(conn net.Conn, requester string, msg map[string]interface{}, clientManager types.ClientManager) {
	unlock := lockGroupOperation(msg)
	defer unlock()
	gid, ok := msg["gid"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_transfer_result", "success": false, "error": "群组ID格式错误"})
		return
	}
	newOwner, ok := msg["new_owner"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_transfer_result", "success": false, "error": "新群主格式错误"})
		return
	}

	log.Printf("event=group_transfer_received")

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("event=group_transfer_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_transfer_result", "success": false, "error": "群组不存在"})
		return
	}

	// 检查请求者是否是群主
	if requester != group.Owner {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_transfer_result", "success": false, "error": "只有群主才能转让群聊"})
		log.Printf("event=group_transfer_failed")
		return
	}

	// 检查新群主是否是群组成员
	isMember := false
	for _, member := range group.Members {
		if member == newOwner {
			isMember = true
			break
		}
	}
	if !isMember {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_transfer_result", "success": false, "error": "新群主必须是群成员"})
		log.Printf("event=group_transfer_failed")
		return
	}

	// 检查是否试图转让给自己
	if newOwner == requester {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_transfer_result", "success": false, "error": "不能转让给自己"})
		log.Printf("event=group_transfer_failed")
		return
	}

	// 更新数据库中的群组所有者
	err = database.UpdateGroupOwner(gid, newOwner)
	if err != nil {
		log.Printf("event=group_transfer_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_transfer_result", "success": false, "error": "转让群主失败"})
		return
	}

	// 更新内存中的群组数据
	group.Owner = newOwner

	// 通知所有成员群主已变更
	transferNotification := map[string]interface{}{
		"type":       "group_transfer_notification",
		"gid":        gid,
		"old_owner":  requester,
		"new_owner":  newOwner,
		"group_name": group.GroupName,
	}

	for _, member := range group.Members {
		if member == requester {
			continue
		}
		if client, found := clientManager.GetClient(member); found {
			protocol.SendMsg(client.Conn, transferNotification)
		}
	}

	// 向请求者确认
	protocol.SendMsg(conn, map[string]interface{}{
		"type":      "group_transfer_result",
		"success":   true,
		"gid":       gid,
		"new_owner": newOwner,
	})
	log.Printf("event=group_transfer_completed")
}

func handleGroupRename(conn net.Conn, requester string, msg map[string]interface{}, clientManager types.ClientManager) {
	unlock := lockGroupOperation(msg)
	defer unlock()
	gid, ok := msg["gid"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_rename_result", "success": false, "error": "群组ID格式错误"})
		return
	}
	newName, ok := msg["new_name"].(string)
	if !ok || !validGroupName(newName) {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_rename_result", "success": false, "error": "群聊名称须为1至128个字符，且不能全为空白"})
		return
	}

	log.Printf("event=group_rename_received")

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("event=group_rename_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_rename_result", "success": false, "error": "群组不存在"})
		return
	}

	// 检查请求者是否是群主
	if requester != group.Owner {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_rename_result", "success": false, "error": "只有群主才能修改群聊名称"})
		log.Printf("event=group_rename_failed")
		return
	}

	// 保存旧名称用于通知
	oldName := groupNameForNotification(group.GroupName)

	// 更新数据库中的群组名称
	err = database.UpdateGroupName(gid, newName)
	if err != nil {
		log.Printf("event=group_rename_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_rename_result", "success": false, "error": "修改群聊名称失败"})
		return
	}

	// 更新内存中的群组数据
	group.GroupName = newName

	// 通知所有成员群组名称已变更
	renameNotification := map[string]interface{}{
		"type":     "group_rename_notification",
		"gid":      gid,
		"old_name": oldName,
		"new_name": newName,
		"owner":    requester,
	}

	for _, member := range group.Members {
		if member == requester {
			continue
		}
		if client, found := clientManager.GetClient(member); found {
			protocol.SendMsg(client.Conn, renameNotification)
		}
	}

	// 向请求者确认
	protocol.SendMsg(conn, map[string]interface{}{
		"type":     "group_rename_result",
		"old_name": oldName,
		"success":  true,
		"gid":      gid,
		"new_name": newName,
	})
	log.Printf("event=group_rename_completed")
}

func handlePrivateChat(conn net.Conn, fromUser string, sessionKey []byte, msg map[string]interface{}, clientManager types.ClientManager) {
	e2eeIdentityMu.RLock()
	defer e2eeIdentityMu.RUnlock()
	toUser, ok := msg["to"].(string)
	if !ok || toUser == "" || toUser == fromUser {
		sendChatResult(conn, "private_chat", msg, 0, "目标用户格式错误")
		return
	}
	friends, err := database.AreFriends(fromUser, toUser)
	if err != nil || !friends {
		sendChatResult(conn, "private_chat", msg, 0, "好友关系校验失败")
		return
	}
	members := []string{fromUser, toUser}
	if _, encrypted := msg["e2ee"]; encrypted {
		handleE2EEChat(conn, fromUser, "private", toUser, members, msg, clientManager)
		return
	}
	required, err := requiresE2EE(members)
	if err != nil || required {
		sendChatResult(conn, "private_chat", msg, 0, "该会话需要端到端加密，请升级客户端并设置加密身份")
		return
	}
	content, ok := msg["content"].(string)
	if !ok {
		sendChatResult(conn, "private_chat", msg, 0, "消息内容格式错误")
		return
	}
	plaintext, err := crypto.DecryptMessage(content, sessionKey)
	if err != nil {
		sendChatResult(conn, "private_chat", msg, 0, "消息解密失败")
		return
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	payload := chatPayload("private_chat", fromUser, toUser, content, timestamp, 9223372036854775807)
	if err := validateReplayableChat(payload); err != nil {
		sendChatResult(conn, "private_chat", msg, 0, "消息内容过长")
		return
	}
	id, err := database.SaveMessageWithID("private", fromUser, toUser, "", plaintext, timestamp)
	if err != nil {
		log.Printf("event=private_chat_failed error_type=%T", err)
		sendChatResult(conn, "private_chat", msg, 0, "消息保存失败，请重试")
		return
	}
	// Receipt acknowledges persistence, independently of recipient delivery.
	sendChatResult(conn, "private_chat", msg, id, "")
	protocol.SendMsg(conn, chatPayload("private_chat", fromUser, toUser, content, timestamp, id))
	if recipient, found := clientManager.GetClient(toUser); found {
		encrypted, err := crypto.EncryptMessage(plaintext, recipient.SessionKey)
		if err != nil {
			log.Printf("event=private_chat_failed error_type=%T", err)
			return
		}
		protocol.SendMsg(recipient.Conn, chatPayload("private_chat", fromUser, toUser, encrypted, timestamp, id))
	}
}

func handleFriendRequest(conn net.Conn, fromUser string, msg map[string]interface{}, clientManager types.ClientManager) {
	toUser, ok := msg["to"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "目标用户格式错误"})
		return
	}

	log.Printf("event=friend_request_received")

	// 不能给自己发好友请求
	if toUser == fromUser {
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "不能添加自己为好友"})
		return
	}

	// 检查目标用户是否存在
	exists, err := database.UserExists(toUser)
	if err != nil {
		log.Printf("event=friend_request_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "服务器内部错误"})
		return
	}
	if !exists {
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "用户 " + toUser + " 不存在"})
		return
	}

	// Acceptance commits under this same lock. Check the friendship while
	// holding it so a retry cannot recreate a request just after acceptance.
	pendingFriendRequestsMu.Lock()
	areFriends, err := database.AreFriends(fromUser, toUser)
	if err != nil {
		pendingFriendRequestsMu.Unlock()
		log.Printf("event=friend_request_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "服务器内部错误"})
		return
	}
	if areFriends {
		pendingFriendRequestsMu.Unlock()
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "您和 " + toUser + " 已是好友"})
		log.Printf("event=friend_request_failed")
		return
	}

	// 记录待处理请求，用于 friend_response 防伪校验
	pruneFriendRequestsLocked(time.Now())
	if pendingFriendRequests[fromUser] == nil {
		pendingFriendRequests[fromUser] = make(map[string]time.Time)
	}
	if _, exists := pendingFriendRequests[fromUser][toUser]; exists {
		pendingFriendRequestsMu.Unlock()
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "已发送过好友申请，请等待对方处理"})
		return
	}
	created := time.Now()
	if err := database.SavePendingFriend(fromUser, toUser, created); err != nil {
		pendingFriendRequestsMu.Unlock()
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "好友申请保存失败，请重试"})
		return
	}
	pendingFriendRequests[fromUser][toUser] = created
	pendingFriendRequestsMu.Unlock()

	// 转发请求给目标用户
	toClient, found := clientManager.GetClient(toUser)
	if found {
		err := protocol.SendMsg(toClient.Conn, map[string]interface{}{"type": "friend_request", "from": fromUser})
		if err != nil {
			log.Printf("event=friend_request_failed error_type=%T", err)
			protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": true, "message": "好友申请已保存，对方重新登录后可见"})
			return
		}
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": true, "message": "好友申请已发送"})
		log.Printf("event=friend_request_received")
	} else {
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": true, "message": "好友申请已保存，对方上线后可见"})
		log.Printf("event=friend_request_failed")
	}
}

func handleGroupChat(conn net.Conn, fromUser string, sessionKey []byte, msg map[string]interface{}, clientManager types.ClientManager) {
	e2eeIdentityMu.RLock()
	defer e2eeIdentityMu.RUnlock()
	unlock := lockGroupOperation(msg)
	defer unlock()
	gid, ok := msg["gid"].(string)
	if !ok || gid == "" {
		sendChatResult(conn, "group_chat", msg, 0, "群组ID格式错误")
		return
	}
	group, err := database.GetGroup(gid)
	if err != nil {
		sendChatResult(conn, "group_chat", msg, 0, "群组不存在")
		return
	}
	member := false
	for _, name := range group.Members {
		if name == fromUser {
			member = true
			break
		}
	}
	if !member {
		sendChatResult(conn, "group_chat", msg, 0, "您不是该群成员")
		return
	}
	if _, encrypted := msg["e2ee"]; encrypted {
		handleE2EEChat(conn, fromUser, "group", gid, group.Members, msg, clientManager)
		return
	}
	required, err := requiresE2EE(group.Members)
	if err != nil || required {
		sendChatResult(conn, "group_chat", msg, 0, "该会话需要端到端加密，请升级客户端并设置加密身份")
		return
	}
	content, ok := msg["content"].(string)
	if !ok {
		sendChatResult(conn, "group_chat", msg, 0, "消息内容格式错误")
		return
	}
	plaintext, err := crypto.DecryptMessage(content, sessionKey)
	if err != nil {
		sendChatResult(conn, "group_chat", msg, 0, "消息解密失败")
		return
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	if err := validateReplayableChat(chatPayload("group_chat", fromUser, gid, content, timestamp, 9223372036854775807)); err != nil {
		sendChatResult(conn, "group_chat", msg, 0, "消息内容过长")
		return
	}
	id, err := database.SaveMessageWithID("group", fromUser, "", gid, plaintext, timestamp)
	if err != nil {
		log.Printf("event=group_chat_failed error_type=%T", err)
		sendChatResult(conn, "group_chat", msg, 0, "消息保存失败，请重试")
		return
	}
	sendChatResult(conn, "group_chat", msg, id, "")
	for _, name := range group.Members {
		if name == fromUser {
			protocol.SendMsg(conn, chatPayload("group_chat", fromUser, gid, content, timestamp, id))
		} else if recipient, found := clientManager.GetClient(name); found {
			encrypted, err := crypto.EncryptMessage(plaintext, recipient.SessionKey)
			if err != nil {
				log.Printf("event=group_chat_failed error_type=%T", err)
				continue
			}
			protocol.SendMsg(recipient.Conn, chatPayload("group_chat", fromUser, gid, encrypted, timestamp, id))
		}
	}
}

func handleGroupCreate(conn net.Conn, owner string, msg map[string]interface{}, clientManager types.ClientManager) {
	groupCatalogMu.RLock()
	defer groupCatalogMu.RUnlock()
	groupName, ok := msg["group_name"].(string)
	if !ok || !validGroupName(groupName) {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": "群聊名称须为1至128个字符，且不能全为空白"})
		return
	}

	membersInterface, ok := msg["members"].([]interface{})
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": "成员列表格式错误"})
		return
	}
	// Bound work before deduplication as well as the final owner-inclusive set.
	if len(membersInterface) > maxGroupMembers {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": groupCapacityError})
		return
	}

	members := []string{owner}
	seen := map[string]bool{owner: true}
	for _, m := range membersInterface {
		memberName, ok := m.(string)
		if !ok || memberName == "" {
			protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": "成员列表格式错误"})
			return
		}
		if seen[memberName] {
			continue
		}
		areFriends, err := database.AreFriends(owner, memberName)
		if err != nil || !areFriends {
			protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": "只能邀请好友创建群聊"})
			return
		}
		seen[memberName] = true
		members = append(members, memberName)
		if len(members) > maxGroupMembers {
			protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": groupCapacityError})
			return
		}
	}

	// 确保群主在成员列表中
	ownerInMembers := false
	for _, member := range members {
		if member == owner {
			ownerInMembers = true
			break
		}
	}
	if !ownerInMembers {
		members = append(members, owner)
	}

	newGroup, err := database.CreateGroup(groupName, owner, members)
	if err != nil {
		log.Printf("event=group_create_failed error_type=%T", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": "创建群组失败"})
		return
	}
	unlock := lockGroup(newGroup.GID)
	defer unlock()

	log.Printf("event=group_created group_id=%s members=%d", groupLogID(newGroup.GID), len(newGroup.Members))

	// 向所有成员广播群组创建成功的信息
	payload := map[string]interface{}{
		"type":       "group_create_result",
		"success":    true,
		"gid":        newGroup.GID,
		"group_name": newGroup.GroupName,
		"owner":      newGroup.Owner,
		"members":    newGroup.Members,
	}

	for _, memberName := range newGroup.Members {
		if client, found := clientManager.GetClient(memberName); found {
			protocol.SendMsg(client.Conn, payload)
		}
	}
}

func handleFriendResponse(conn net.Conn, responder string, msg map[string]interface{}, clientManager types.ClientManager) {
	fromUser, ok := msg["to"].(string) // 这里的 "to" 是请求发起者
	if !ok {
		log.Printf("event=invalid_message_type")
		return
	}
	accepted, ok := msg["accepted"].(bool)
	if !ok {
		log.Printf("event=invalid_message_type")
		return
	}

	log.Printf("event=friend_response_received")

	// 防伪校验：仅当请求发起者确实向本用户发送过好友请求时才允许响应
	pendingFriendRequestsMu.Lock()
	pruneFriendRequestsLocked(time.Now())
	if pendingFriendRequests[fromUser] == nil {
		pendingFriendRequestsMu.Unlock()
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_response_result", "success": false, "error": "没有来自该用户的好友请求，无法响应"})
		log.Printf("event=friend_response_denied")
		return
	}
	if _, exists := pendingFriendRequests[fromUser][responder]; !exists {
		pendingFriendRequestsMu.Unlock()
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_response_result", "success": false, "error": "没有来自该用户的好友请求，无法响应"})
		log.Printf("event=friend_response_denied")
		return
	}
	// Persist before acknowledging acceptance or consuming the request. A failed
	// transaction must leave the request available for the responder to retry.
	if accepted {
		if err := database.SaveFriendRelationship(responder, fromUser); err != nil {
			pendingFriendRequestsMu.Unlock()
			protocol.SendMsg(conn, map[string]interface{}{"type": "friend_response_result", "success": false, "error": "保存好友关系失败"})
			return
		}
	}
	if !accepted {
		if err := database.DeletePendingFriend(fromUser, responder); err != nil {
			pendingFriendRequestsMu.Unlock()
			protocol.SendMsg(conn, map[string]interface{}{"type": "friend_response_result", "success": false, "error": "申请处理失败，请重试"})
			return
		}
	}
	// 请求已处理，移除待处理记录
	delete(pendingFriendRequests[fromUser], responder)
	if len(pendingFriendRequests[fromUser]) == 0 {
		delete(pendingFriendRequests, fromUser)
	}
	if accepted {
		delete(pendingFriendRequests[responder], fromUser)
		if len(pendingFriendRequests[responder]) == 0 {
			delete(pendingFriendRequests, responder)
		}
	}
	pendingFriendRequestsMu.Unlock()

	// 转发响应给请求发起者
	fromClient, found := clientManager.GetClient(fromUser)
	if found {
		err := protocol.SendMsg(fromClient.Conn, map[string]interface{}{
			"type":     "friend_response",
			"from":     responder,
			"accepted": accepted,
		})
		if err != nil {
			log.Printf("event=friend_response_failed error_type=%T", err)
		}
	} else {
		log.Printf("event=friend_response_failed")
	}

	if accepted {
		log.Printf("event=friend_response_completed")

		// 通知双方更新好友列表
		// 通知响应者
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_update", "friend": fromUser})
		// 通知请求发起者
		if fromClient != nil { // 确保请求发起者仍然在线
			protocol.SendMsg(fromClient.Conn, map[string]interface{}{"type": "friend_update", "friend": responder})
		}
	}
}
