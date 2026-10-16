package handlers

import (
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"chatroom/internal/types"
	"fmt"
	"net"
)

// SendFriendsAndActivate publishes a fresh friends snapshot before the session
// becomes visible to senders. The successful login reply must already be sent
// and queued writes enabled, so no network write blocks the request lock.
func SendFriendsAndActivate(conn net.Conn, username string, manager types.ClientManager) error {
	// Accepted requests commit under this same lock. An acceptance is therefore
	// either included in this snapshot or delivered after it as a friend_update.
	pendingFriendRequestsMu.Lock()
	defer pendingFriendRequestsMu.Unlock()
	friends, err := database.LoadFriends(username)
	if err != nil {
		return err
	}
	list := make([]string, 0, len(friends))
	for friend := range friends {
		list = append(list, friend)
	}
	if err := protocol.SendMsg(conn, map[string]interface{}{"type": "friends_list", "friends": list}); err != nil {
		return err
	}
	if !manager.ActivateClient(username, conn) {
		return fmt.Errorf("login reservation no longer belongs to connection")
	}
	return nil
}
