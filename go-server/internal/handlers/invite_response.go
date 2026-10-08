package handlers

import (
	"chatroom/internal/protocol"
	"net"
	"time"
)

// Accepting continues to use group_join; this response explicitly declines.
func handleGroupInviteResponse(conn net.Conn, username string, msg map[string]interface{}) {
	gid, ok := msg["gid"].(string)
	accepted, valid := msg["accepted"].(bool)
	if !ok || gid == "" || !valid || accepted {
		protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_response_result", "success": false, "error": "拒绝邀请参数错误，请使用 group_join 接受邀请"})
		return
	}
	unlock := lockGroupOperation(msg)
	defer unlock()
	pendingGroupJoinsMu.Lock()
	pruneGroupInvitesLocked(time.Now())
	delete(pendingGroupJoins[gid], username)
	if len(pendingGroupJoins[gid]) == 0 {
		delete(pendingGroupJoins, gid)
	}
	pendingGroupJoinsMu.Unlock()
	protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite_response_result", "success": true, "gid": gid})
}
