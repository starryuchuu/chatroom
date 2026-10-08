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

	"chatroom/internal/types" // 导入 types 包以访问 ClientManager 接口
)

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
			log.Printf("从用户 %s 接收消息失败: %v", username, err)
			break // 退出循环，连接将在上层关闭
		}

		msgType, ok := msg["type"].(string)
		if !ok {
			log.Printf("收到来自 %s 的消息格式错误: %v", username, msg)
			continue
		}

		log.Printf("收到来自 %s 的消息类型: %s", username, msgType) // 不记录消息内容，避免日志泄露

		switch msgType {
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
			log.Printf("未知的消息类型: %s", msgType)
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

	log.Printf("处理来自 '%s' 到 '%s' 的群组邀请，群组ID: %s", inviter, toUser, gid)

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("群组邀请失败，无法获取群组 %s: %v", gid, err)
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
		log.Printf("群组邀请从 '%s' 失败: 不是群组成员", inviter)
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
		log.Printf("群组邀请从 '%s' 失败: 用户 '%s' 已是群组成员", inviter, toUser)
		return
	}

	// 检查被邀请用户是否存在
	exists, err := database.UserExists(toUser)
	if err != nil {
		log.Printf("检查用户 %s 存在性失败: %v", toUser, err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "服务器内部错误"})
		return
	}
	if !exists {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "用户 " + toUser + " 不存在"})
		log.Printf("群组邀请从 '%s' 失败: 用户 '%s' 不存在", inviter, toUser)
		return
	}

	// 检查是否是好友关系（直接查询数据库而不是依赖在线客户端信息）
	areFriends, err := database.AreFriends(inviter, toUser)
	if err != nil {
		log.Printf("检查好友关系失败 (%s, %s): %v", inviter, toUser, err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "服务器内部错误"})
		return
	}
	if !areFriends {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "您和 " + toUser + " 不是好友关系"})
		log.Printf("群组邀请从 '%s' 到 '%s' 失败: 不是好友", inviter, toUser)
		return
	}

	// 记录待加入请求（仅收到过邀请的用户才能 join，防止越权加入）
	pendingGroupJoinsMu.Lock()
	pruneGroupInvitesLocked(time.Now())
	if pendingGroupJoins[gid] == nil {
		pendingGroupJoins[gid] = make(map[string]groupInvitation)
	}
	pendingGroupJoins[gid][toUser] = groupInvitation{Inviter: inviter, CreatedAt: time.Now()}
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
			log.Printf("转发群组邀请给 %s 失败: %v", toUser, err)
			protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": true, "message": "邀请已保存，对方重新登录后可见"})
			return
		}
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": true, "message": "已向 " + toUser + " 发送邀请"})
		log.Printf("群组邀请从 '%s' 转发到 '%s'，群组ID: %s", inviter, toUser, gid)
	} else {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": true, "message": "邀请已保存，对方上线后可见"})
		log.Printf("群组邀请从 '%s' 到 '%s' 失败: 用户不在线", inviter, toUser)
	}
}

func handleGroupJoin(conn net.Conn, userToJoin string, msg map[string]interface{}, clientManager types.ClientManager) {
	unlock := lockGroupOperation(msg)
	defer unlock()
	gid, ok := msg["gid"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_join_result", "success": false, "error": "群组ID格式错误"})
		return
	}

	log.Printf("处理用户 '%s' 加入群组 '%s' 的请求", userToJoin, gid)

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("群组加入失败，无法获取群组 %s: %v", gid, err)
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
		log.Printf("用户 '%s' 加入群组 '%s' 失败: 已是群组成员", userToJoin, gid)
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
		log.Printf("用户 '%s' 加入群组 '%s' 被阻止: 无待处理邀请", userToJoin, gid)
		return
	}
	pendingGroupJoinsMu.Unlock()

	// 添加用户到群组成员列表
	group.Members = append(group.Members, userToJoin)

	// 更新数据库中的群组成员
	err = database.UpdateGroupMembers(gid, group.Members)
	if err != nil {
		log.Printf("更新群组成员失败: %v", err)
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
	log.Printf("用户 '%s' 成功加入群组 '%s'", userToJoin, gid)

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

	log.Printf("处理用户 '%s' 离开群组 '%s' 的请求", userToLeave, gid)

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("群组离开失败，无法获取群组 %s: %v", gid, err)
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
		log.Printf("用户 '%s' 离开群组 '%s' 失败: 不是群组成员", userToLeave, gid)
		return
	}

	// 检查用户是否是群主
	if userToLeave == group.Owner {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_leave_result", "success": false, "error": "群主不能直接退出群聊，请先解散群聊或转让群主"})
		log.Printf("用户 '%s' 离开群组 '%s' 失败: 是群主", userToLeave, gid)
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
		log.Printf("更新群组成员失败: %v", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_leave_result", "success": false, "error": "退出失败"})
		return
	}

	// 发送成功响应给离开者
	protocol.SendMsg(conn, map[string]interface{}{
		"type":    "group_leave_result",
		"success": true,
		"gid":     gid,
	})
	log.Printf("用户 '%s' 成功离开群组 '%s'", userToLeave, gid)

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

	log.Printf("处理用户 '%s' 踢出用户 '%s' 从群组 '%s' 的请求", requester, kickUser, gid)

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("群组踢人失败，无法获取群组 %s: %v", gid, err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_kick_result", "success": false, "error": "群组不存在"})
		return
	}

	// 检查请求者是否是群主
	if requester != group.Owner {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_kick_result", "success": false, "error": "只有群主才能踢人"})
		log.Printf("用户 '%s' 踢出用户 '%s' 从群组 '%s' 失败: 不是群主", requester, kickUser, gid)
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
		log.Printf("用户 '%s' 踢出用户 '%s' 从群组 '%s' 失败: 被踢用户不是群组成员", requester, kickUser, gid)
		return
	}

	// 检查是否试图踢自己
	if kickUser == requester {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_kick_result", "success": false, "error": "不能踢自己"})
		log.Printf("用户 '%s' 踢出自己从群组 '%s' 失败: 不能踢自己", requester, gid)
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
		log.Printf("更新群组成员失败: %v", err)
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
	log.Printf("用户 '%s' 成功踢出用户 '%s' 从群组 '%s'", requester, kickUser, gid)

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

	log.Printf("处理用户 '%s' 获取群组 '%s' 信息的请求", username, gid)

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("获取群组信息失败，无法获取群组 %s: %v", gid, err)
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
		log.Printf("用户 '%s' 获取群组 '%s' 信息被阻止: 不是群成员", username, gid)
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
	log.Printf("成功发送群组 '%s' 信息给用户 '%s'", gid, username)
}

func handleGroupDisband(conn net.Conn, requester string, msg map[string]interface{}, clientManager types.ClientManager) {
	unlock := lockGroupOperation(msg)
	defer unlock()
	gid, ok := msg["gid"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_disband_result", "success": false, "error": "群组ID格式错误"})
		return
	}

	log.Printf("处理用户 '%s' 解散群组 '%s' 的请求", requester, gid)

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("解散群组失败，无法获取群组 %s: %v", gid, err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_disband_result", "success": false, "error": "群组不存在"})
		return
	}

	// 检查请求者是否是群主
	if requester != group.Owner {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_disband_result", "success": false, "error": "只有群主才能解散群聊"})
		log.Printf("用户 '%s' 解散群组 '%s' 失败: 不是群主", requester, gid)
		return
	}

	// 从数据库中删除群组
	err = database.DeleteGroup(gid)
	if err != nil {
		log.Printf("删除群组失败: %v", err)
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
	log.Printf("用户 '%s' 成功解散群组 '%s'", requester, gid)
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

	log.Printf("处理用户 '%s' 转让群组 '%s' 给 '%s' 的请求", requester, gid, newOwner)

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("转让群组失败，无法获取群组 %s: %v", gid, err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_transfer_result", "success": false, "error": "群组不存在"})
		return
	}

	// 检查请求者是否是群主
	if requester != group.Owner {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_transfer_result", "success": false, "error": "只有群主才能转让群聊"})
		log.Printf("用户 '%s' 转让群组 '%s' 失败: 不是群主", requester, gid)
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
		log.Printf("用户 '%s' 转让群组 '%s' 失败: 新群主 '%s' 不是群组成员", requester, gid, newOwner)
		return
	}

	// 检查是否试图转让给自己
	if newOwner == requester {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_transfer_result", "success": false, "error": "不能转让给自己"})
		log.Printf("用户 '%s' 转让群组 '%s' 失败: 不能转让给自己", requester, gid)
		return
	}

	// 更新数据库中的群组所有者
	err = database.UpdateGroupOwner(gid, newOwner)
	if err != nil {
		log.Printf("更新群组所有者失败: %v", err)
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
	log.Printf("用户 '%s' 成功转让群组 '%s' 给 '%s'", requester, gid, newOwner)
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
	if !ok || newName == "" {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_rename_result", "success": false, "error": "群聊名称不能为空"})
		return
	}

	log.Printf("处理用户 '%s' 重命名群组 '%s' 为 '%s' 的请求", requester, gid, newName)

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("重命名群组失败，无法获取群组 %s: %v", gid, err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_rename_result", "success": false, "error": "群组不存在"})
		return
	}

	// 检查请求者是否是群主
	if requester != group.Owner {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_rename_result", "success": false, "error": "只有群主才能修改群聊名称"})
		log.Printf("用户 '%s' 重命名群组 '%s' 失败: 不是群主", requester, gid)
		return
	}

	// 保存旧名称用于通知
	oldName := group.GroupName

	// 更新数据库中的群组名称
	err = database.UpdateGroupName(gid, newName)
	if err != nil {
		log.Printf("更新群组名称失败: %v", err)
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
	log.Printf("用户 '%s' 成功重命名群组 '%s' 从 '%s' 为 '%s'", requester, gid, oldName, newName)
}

func handlePrivateChat(conn net.Conn, fromUser string, sessionKey []byte, msg map[string]interface{}, clientManager types.ClientManager) {
	toUser, ok := msg["to"].(string)
	if !ok || toUser == "" || toUser == fromUser {
		sendChatResult(conn, "private_chat", msg, 0, "目标用户格式错误")
		return
	}
	content, ok := msg["content"].(string)
	if !ok {
		sendChatResult(conn, "private_chat", msg, 0, "消息内容格式错误")
		return
	}
	friends, err := database.AreFriends(fromUser, toUser)
	if err != nil || !friends {
		sendChatResult(conn, "private_chat", msg, 0, "好友关系校验失败")
		return
	}
	plaintext, err := crypto.DecryptMessage(content, sessionKey)
	if err != nil {
		sendChatResult(conn, "private_chat", msg, 0, "消息解密失败")
		return
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	payload := chatPayload("private_chat", fromUser, toUser, content, timestamp, 9223372036854775807)
	if err := protocol.ValidateMessage(payload); err != nil {
		sendChatResult(conn, "private_chat", msg, 0, "消息内容过长")
		return
	}
	id, err := database.SaveMessageWithID("private", fromUser, toUser, "", plaintext, timestamp)
	if err != nil {
		log.Printf("保存私聊消息失败: %v", err)
		sendChatResult(conn, "private_chat", msg, 0, "消息保存失败，请重试")
		return
	}
	// Receipt acknowledges persistence, independently of recipient delivery.
	sendChatResult(conn, "private_chat", msg, id, "")
	protocol.SendMsg(conn, chatPayload("private_chat", fromUser, toUser, content, timestamp, id))
	if recipient, found := clientManager.GetClient(toUser); found {
		encrypted, err := crypto.EncryptMessage(plaintext, recipient.SessionKey)
		if err != nil {
			log.Printf("加密发送给 %s 的消息失败: %v", toUser, err)
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

	log.Printf("处理来自 '%s' 到 '%s' 的好友请求", fromUser, toUser)

	// 不能给自己发好友请求
	if toUser == fromUser {
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "不能添加自己为好友"})
		return
	}

	// 检查目标用户是否存在
	exists, err := database.UserExists(toUser)
	if err != nil {
		log.Printf("检查用户 %s 存在性失败: %v", toUser, err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "服务器内部错误"})
		return
	}
	if !exists {
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "用户 " + toUser + " 不存在"})
		return
	}

	// 检查是否已经是好友，防止重复申请骚扰
	areFriends, err := database.AreFriends(fromUser, toUser)
	if err != nil {
		log.Printf("检查好友关系失败 (%s, %s): %v", fromUser, toUser, err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "服务器内部错误"})
		return
	}
	if areFriends {
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "您和 " + toUser + " 已是好友"})
		log.Printf("好友请求从 '%s' 到 '%s' 失败: 已是好友", fromUser, toUser)
		return
	}

	// 记录待处理请求，用于 friend_response 防伪校验
	pendingFriendRequestsMu.Lock()
	pruneFriendRequestsLocked(time.Now())
	if pendingFriendRequests[fromUser] == nil {
		pendingFriendRequests[fromUser] = make(map[string]time.Time)
	}
	if _, exists := pendingFriendRequests[fromUser][toUser]; exists {
		pendingFriendRequestsMu.Unlock()
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "已发送过好友申请，请等待对方处理"})
		return
	}
	pendingFriendRequests[fromUser][toUser] = time.Now()
	pendingFriendRequestsMu.Unlock()

	// 转发请求给目标用户
	toClient, found := clientManager.GetClient(toUser)
	if found {
		err := protocol.SendMsg(toClient.Conn, map[string]interface{}{"type": "friend_request", "from": fromUser})
		if err != nil {
			log.Printf("转发好友请求给 %s 失败: %v", toUser, err)
			protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": true, "message": "好友申请已保存，对方重新登录后可见"})
			return
		}
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": true, "message": "好友申请已发送"})
		log.Printf("好友请求从 '%s' 转发到 '%s'", fromUser, toUser)
	} else {
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": true, "message": "好友申请已保存，对方上线后可见"})
		log.Printf("好友请求从 '%s' 到 '%s' 失败: 用户不在线", fromUser, toUser)
	}
}

func handleGroupChat(conn net.Conn, fromUser string, sessionKey []byte, msg map[string]interface{}, clientManager types.ClientManager) {
	unlock := lockGroupOperation(msg)
	defer unlock()
	gid, ok := msg["gid"].(string)
	if !ok || gid == "" {
		sendChatResult(conn, "group_chat", msg, 0, "群组ID格式错误")
		return
	}
	content, ok := msg["content"].(string)
	if !ok {
		sendChatResult(conn, "group_chat", msg, 0, "消息内容格式错误")
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
	plaintext, err := crypto.DecryptMessage(content, sessionKey)
	if err != nil {
		sendChatResult(conn, "group_chat", msg, 0, "消息解密失败")
		return
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	if err := protocol.ValidateMessage(chatPayload("group_chat", fromUser, gid, content, timestamp, 9223372036854775807)); err != nil {
		sendChatResult(conn, "group_chat", msg, 0, "消息内容过长")
		return
	}
	id, err := database.SaveMessageWithID("group", fromUser, "", gid, plaintext, timestamp)
	if err != nil {
		log.Printf("保存群聊消息失败: %v", err)
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
				log.Printf("加密群消息失败: %v", err)
				continue
			}
			protocol.SendMsg(recipient.Conn, chatPayload("group_chat", fromUser, gid, encrypted, timestamp, id))
		}
	}
}

func handleGroupCreate(conn net.Conn, owner string, msg map[string]interface{}, clientManager types.ClientManager) {
	groupName, ok := msg["group_name"].(string)
	if !ok || strings.TrimSpace(groupName) == "" {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": "群组名称无效"})
		return
	}

	membersInterface, ok := msg["members"].([]interface{})
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": "成员列表格式错误"})
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
		log.Printf("创建群组 '%s' 失败: %v", groupName, err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": "创建群组失败"})
		return
	}
	unlock := lockGroupOperation(map[string]interface{}{"gid": newGroup.GID})
	defer unlock()

	log.Printf("用户 '%s' 创建了新群组 '%s' (GID: %s)", owner, groupName, newGroup.GID)

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
		log.Printf("好友响应消息格式错误: 缺少 'to' 字段")
		return
	}
	accepted, ok := msg["accepted"].(bool)
	if !ok {
		log.Printf("好友响应消息格式错误: 'accepted' 字段无效")
		return
	}

	log.Printf("处理来自 '%s' 到 '%s' 的好友响应。接受: %t", responder, fromUser, accepted)

	// 防伪校验：仅当请求发起者确实向本用户发送过好友请求时才允许响应
	pendingFriendRequestsMu.Lock()
	pruneFriendRequestsLocked(time.Now())
	if pendingFriendRequests[fromUser] == nil {
		pendingFriendRequestsMu.Unlock()
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_response_result", "success": false, "error": "没有来自该用户的好友请求，无法响应"})
		log.Printf("好友响应从 '%s' 到 '%s' 被阻止: 无待处理请求", responder, fromUser)
		return
	}
	if _, exists := pendingFriendRequests[fromUser][responder]; !exists {
		pendingFriendRequestsMu.Unlock()
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_response_result", "success": false, "error": "没有来自该用户的好友请求，无法响应"})
		log.Printf("好友响应从 '%s' 到 '%s' 被阻止: 无待处理请求", responder, fromUser)
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
	// 请求已处理，移除待处理记录
	delete(pendingFriendRequests[fromUser], responder)
	if len(pendingFriendRequests[fromUser]) == 0 {
		delete(pendingFriendRequests, fromUser)
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
			log.Printf("转发好友响应给 %s 失败: %v", fromUser, err)
		}
	} else {
		log.Printf("好友响应从 '%s' 到 '%s' 失败: 请求发起者不在线", responder, fromUser)
	}

	if accepted {
		log.Printf("好友关系 '%s' 和 '%s' 已保存", responder, fromUser)

		// 通知双方更新好友列表
		// 通知响应者
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_update", "friend": fromUser})
		// 通知请求发起者
		if fromClient != nil { // 确保请求发起者仍然在线
			protocol.SendMsg(fromClient.Conn, map[string]interface{}{"type": "friend_update", "friend": responder})
		}
	}
}
