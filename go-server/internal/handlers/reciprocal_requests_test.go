package handlers

import (
	"chatroom/internal/database"
	"testing"
)

func TestAcceptingReciprocalRequestConsumesBothDirections(t *testing.T) {
	manager := setupHandlers(t)
	handleFriendRequest(&recordConn{}, "alice", map[string]interface{}{"to": "bob"}, manager)
	handleFriendRequest(&recordConn{}, "bob", map[string]interface{}{"to": "alice"}, manager)

	handleFriendResponse(&recordConn{}, "bob", map[string]interface{}{"to": "alice", "accepted": true}, manager)
	if len(pendingFriendRequests) != 0 {
		t.Fatal("acceptance left a reciprocal request for existing friends")
	}
	friends, _, err := database.LoadPendingRequests()
	if err != nil || len(friends) != 0 {
		t.Fatalf("reciprocal request survives restart: %v %v", friends, err)
	}
	for _, name := range []string{"alice", "bob"} {
		conn := &recordConn{}
		SendPendingNotifications(conn, name)
		if len(conn.messages(t)) != 0 {
			t.Fatalf("existing friend %s received a stale request", name)
		}
	}
}

func TestDecliningReciprocalRequestPreservesOtherDirection(t *testing.T) {
	manager := setupHandlers(t)
	handleFriendRequest(&recordConn{}, "alice", map[string]interface{}{"to": "bob"}, manager)
	handleFriendRequest(&recordConn{}, "bob", map[string]interface{}{"to": "alice"}, manager)

	handleFriendResponse(&recordConn{}, "bob", map[string]interface{}{"to": "alice", "accepted": false}, manager)
	if len(pendingFriendRequests) != 1 || len(pendingFriendRequests["bob"]) != 1 {
		t.Fatal("decline consumed the independent reciprocal request")
	}
	friends, _, err := database.LoadPendingRequests()
	if err != nil || len(friends) != 1 || friends[0].Requester != "bob" || friends[0].Target != "alice" {
		t.Fatalf("wrong durable request retained: %v %v", friends, err)
	}
}
