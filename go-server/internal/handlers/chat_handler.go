package handlers

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"log"
	"net"
	"time"

	"chatroom/internal/types" // 导入 types 包以访问 ClientManager 接口
)

// HandleClientMessages 处理认证成功后的客户端消息循环
func HandleClientMessages(conn net.Conn, username string, sessionKey []byte, clientManager types.ClientManager) {
	for {
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

		log.Printf("收到来自 %s 的消息类型: %s, 内容: %v", username, msgType, msg)

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
			protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "转发群组邀请失败"})
			return
		}
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": true, "message": "已向 " + toUser + " 发送邀请"})
		log.Printf("群组邀请从 '%s' 转发到 '%s'，群组ID: %s", inviter, toUser, gid)
	} else {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_result", "success": false, "error": "用户 " + toUser + " 不在线"})
		log.Printf("群组邀请从 '%s' 到 '%s' 失败: 用户不在线", inviter, toUser)
	}
}

func handleGroupJoin(conn net.Conn, userToJoin string, msg map[string]interface{}, clientManager types.ClientManager) {
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

	// 添加用户到群组成员列表
	group.Members = append(group.Members, userToJoin)

	// 更新数据库中的群组成员
	err = database.UpdateGroupMembers(gid, group.Members)
	if err != nil {
		log.Printf("更新群组成员失败: %v", err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_join_result", "success": false, "error": "加入失败"})
		return
	}

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

	// 通知所有成员群组已解散
	disbandNotification := map[string]interface{}{
		"type":       "group_disband_notification",
		"gid":        gid,
		"group_name": group.GroupName,
	}

	for _, member := range group.Members {
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
		if client, found := clientManager.GetClient(member); found {
			protocol.SendMsg(client.Conn, renameNotification)
		}
	}

	// 向请求者确认
	protocol.SendMsg(conn, map[string]interface{}{
		"type":     "group_rename_result",
		"success":  true,
		"gid":      gid,
		"new_name": newName,
	})
	log.Printf("用户 '%s' 成功重命名群组 '%s' 从 '%s' 为 '%s'", requester, gid, oldName, newName)
}

func handlePrivateChat(conn net.Conn, fromUser string, sessionKey []byte, msg map[string]interface{}, clientManager types.ClientManager) {
	toUser, ok := msg["to"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "private_chat_result", "success": false, "error": "目标用户格式错误"})
		return
	}
	encryptedContent, ok := msg["content"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "private_chat_result", "success": false, "error": "消息内容格式错误"})
		return
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05") // Go的时间格式化

	if toUser == fromUser {
		log.Printf("用户 '%s' 尝试给自己发送私聊消息", fromUser)
		return
	}

	// 检查是否是好友关系 (TODO: 需要从数据库加载好友列表)
	// 暂时跳过好友检查，后续实现好友管理时再添加

	plaintext, err := crypto.DecryptMessage(encryptedContent, sessionKey)
	if err != nil {
		log.Printf("解密来自 %s 的私聊消息失败: %v", fromUser, err)
		return
	}

	err = database.SaveMessage("private", fromUser, toUser, "", plaintext, timestamp)
	if err != nil {
		log.Printf("保存私聊消息失败: %v", err)
		return
	}
	log.Printf("私聊消息从 '%s' 到 '%s' 已保存到数据库", fromUser, toUser)

	// 准备发送给接收者的消息
	recipientClient, found := clientManager.GetClient(toUser)
	if found {
		encryptedMsgForRecipient, err := crypto.EncryptMessage(plaintext, recipientClient.SessionKey)
		if err != nil {
			log.Printf("加密发送给 %s 的消息失败: %v", toUser, err)
			return
		}
		messageForRecipient := map[string]interface{}{
			"type":      "private_chat",
			"from":      fromUser,
			"to":        toUser,
			"content":   encryptedMsgForRecipient,
			"timestamp": timestamp,
		}
		protocol.SendMsg(recipientClient.Conn, messageForRecipient)
		log.Printf("私聊消息从 '%s' 转发到 '%s'", fromUser, toUser)
	} else {
		log.Printf("用户 '%s' 不在线，无法发送私聊消息", toUser)
		// 可以选择通知发送者对方不在线
	}

	// 准备发送给发送者的消息（用于客户端显示）
	encryptedMsgForSender, err := crypto.EncryptMessage(plaintext, sessionKey)
	if err != nil {
		log.Printf("加密发送给 %s 的消息失败: %v", fromUser, err)
		return
	}
	messageForSender := map[string]interface{}{
		"type":      "private_chat",
		"from":      fromUser,
		"to":        toUser,
		"content":   encryptedMsgForSender,
		"timestamp": timestamp,
	}
	protocol.SendMsg(conn, messageForSender)
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

	// 检查是否已经是好友 (TODO: 需要加载好友列表)
	// 暂时跳过好友检查

	// 转发请求给目标用户
	toClient, found := clientManager.GetClient(toUser)
	if found {
		err := protocol.SendMsg(toClient.Conn, map[string]interface{}{"type": "friend_request", "from": fromUser})
		if err != nil {
			log.Printf("转发好友请求给 %s 失败: %v", toUser, err)
			protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "转发好友请求失败"})
			return
		}
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": true, "message": "好友申请已发送"})
		log.Printf("好友请求从 '%s' 转发到 '%s'", fromUser, toUser)
	} else {
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request_result", "success": false, "error": "用户 " + toUser + " 不在线"})
		log.Printf("好友请求从 '%s' 到 '%s' 失败: 用户不在线", fromUser, toUser)
	}
}

func handleGroupChat(conn net.Conn, fromUser string, sessionKey []byte, msg map[string]interface{}, clientManager types.ClientManager) {
	gid, ok := msg["gid"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_chat_result", "success": false, "error": "群组ID格式错误"})
		return
	}
	encryptedContent, ok := msg["content"].(string)
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_chat_result", "success": false, "error": "消息内容格式错误"})
		return
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	group, err := database.GetGroup(gid)
	if err != nil {
		log.Printf("处理群聊消息失败，无法获取群组 %s: %v", gid, err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_chat_result", "success": false, "error": "群组不存在"})
		return
	}

	// 检查用户是否是群成员
	isMember := false
	for _, member := range group.Members {
		if member == fromUser {
			isMember = true
			break
		}
	}
	if !isMember {
		log.Printf("用户 %s 尝试向非成员群组 %s 发送消息", fromUser, gid)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_chat_result", "success": false, "error": "您不是该群成员"})
		return
	}

	plaintext, err := crypto.DecryptMessage(encryptedContent, sessionKey)
	if err != nil {
		log.Printf("解密来自 %s 的群聊消息失败: %v", fromUser, err)
		return
	}

	err = database.SaveMessage("group", fromUser, "", gid, plaintext, timestamp)
	if err != nil {
		log.Printf("保存群聊消息失败: %v", err)
		return
	}
	log.Printf("群聊消息从 '%s' 到群组 '%s' 已保存", fromUser, gid)

	// 向所有在线的群成员广播消息
	for _, memberName := range group.Members {
		if recipientClient, found := clientManager.GetClient(memberName); found {
			encryptedMsg, err := crypto.EncryptMessage(plaintext, recipientClient.SessionKey)
			if err != nil {
				log.Printf("加密发送给群成员 %s 的消息失败: %v", memberName, err)
				continue
			}
			messageToSend := map[string]interface{}{
				"type":      "group_chat",
				"from":      fromUser,
				"gid":       gid,
				"content":   encryptedMsg,
				"timestamp": timestamp,
			}
			protocol.SendMsg(recipientClient.Conn, messageToSend)
		}
	}
}

func handleGroupCreate(conn net.Conn, owner string, msg map[string]interface{}, clientManager types.ClientManager) {
	groupName, ok := msg["group_name"].(string)
	if !ok || groupName == "" {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": "群组名称无效"})
		return
	}

	membersInterface, ok := msg["members"].([]interface{})
	if !ok {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": "成员列表格式错误"})
		return
	}

	var members []string
	for _, m := range membersInterface {
		if memberName, ok := m.(string); ok {
			members = append(members, memberName)
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
		log.Printf("创建群组 '%s' 失败: %v", groupName, err)
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_create_result", "success": false, "error": "创建群组失败"})
		return
	}

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
		// 保存好友关系到数据库
		err := database.SaveFriendRelationship(responder, fromUser)
		if err != nil {
			log.Printf("保存好友关系失败: %v", err)
			// 即使保存失败，也尝试通知客户端
			protocol.SendMsg(conn, map[string]interface{}{"type": "friend_response_result", "success": false, "error": "保存好友关系失败"})
			return
		}
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
