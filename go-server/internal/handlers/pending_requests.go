package handlers

import (
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"net"
	"time"
)

const pendingRequestTTL = 24 * time.Hour

type groupInvitation struct {
	Inviter   string
	CreatedAt time.Time
}

func pruneFriendRequestsLocked(now time.Time) {
	for from, targets := range pendingFriendRequests {
		for target, created := range targets {
			if now.Sub(created) >= pendingRequestTTL {
				delete(targets, target)
			}
		}
		if len(targets) == 0 {
			delete(pendingFriendRequests, from)
		}
	}
}
func pruneGroupInvitesLocked(now time.Time) {
	for gid, targets := range pendingGroupJoins {
		for target, invite := range targets {
			if now.Sub(invite.CreatedAt) >= pendingRequestTTL {
				delete(targets, target)
			}
		}
		if len(targets) == 0 {
			delete(pendingGroupJoins, gid)
		}
	}
}

// SendPendingNotifications replays still-pending in-memory requests after login.
// Network writes happen after releasing the shared request maps' locks.
func SendPendingNotifications(conn net.Conn, username string) {
	var requesters []string
	pendingFriendRequestsMu.Lock()
	pruneFriendRequestsLocked(time.Now())
	for from, targets := range pendingFriendRequests {
		if _, ok := targets[username]; ok {
			requesters = append(requesters, from)
		}
	}
	pendingFriendRequestsMu.Unlock()
	for _, from := range requesters {
		protocol.SendMsg(conn, map[string]interface{}{"type": "friend_request", "from": from})
	}
	invites := make(map[string]groupInvitation)
	pendingGroupJoinsMu.Lock()
	pruneGroupInvitesLocked(time.Now())
	for gid, targets := range pendingGroupJoins {
		if invite, ok := targets[username]; ok {
			invites[gid] = invite
		}
	}
	pendingGroupJoinsMu.Unlock()
	for gid, invite := range invites {
		group, err := database.GetGroup(gid)
		if err == nil {
			protocol.SendMsg(conn, map[string]interface{}{"type": "group_invite", "from": invite.Inviter, "gid": gid, "group_name": group.GroupName})
		}
	}
}
