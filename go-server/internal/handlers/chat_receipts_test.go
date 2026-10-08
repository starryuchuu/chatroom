package handlers

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"strings"
	"testing"
	"time"
)

func TestPrivateAndGroupReceiptsMatchStoredAndForwardedIDs(t *testing.T) {
	manager := setupHandlers(t)
	key := []byte("0123456789abcdef")
	alice, bob := &recordConn{}, &recordConn{}
	manager.AddClient("alice", alice, key, nil)
	manager.AddClient("bob", bob, key, nil)
	database.SaveFriendRelationship("alice", "bob")
	group, _ := database.CreateGroup("Team", "alice", []string{"alice", "bob"})
	content, _ := crypto.EncryptMessage("hello", key)
	handlePrivateChat(alice, "alice", key, map[string]interface{}{"to": "bob", "content": content, "request_id": "private"}, manager)
	handleGroupChat(alice, "alice", key, map[string]interface{}{"gid": group.GID, "content": content, "request_id": "group"}, manager)
	for _, kind := range []string{"private_chat", "group_chat"} {
		receipt := alice.result(t, kind+"_result")
		if receipt["success"] != true || receipt["request_id"] != strings.TrimSuffix(kind, "_chat") {
			t.Fatalf("%v", receipt)
		}
		if receipt["message_id"] != alice.result(t, kind)["message_id"] || receipt["message_id"] != bob.result(t, kind)["message_id"] {
			t.Fatal("receipt and delivery IDs differ")
		}
	}
	history, _, err := database.GetChatHistorySnapshot("bob")
	if err != nil || len(history) != 2 {
		t.Fatalf("%v %v", history, err)
	}
	if float64(history[0].ID) != alice.result(t, "private_chat_result")["message_id"] {
		t.Fatal("history ID differs")
	}
}

func TestChatSaveFailureHasRequestIDAndDoesNotForward(t *testing.T) {
	manager := setupHandlers(t)
	key := []byte("0123456789abcdef")
	alice, bob := &recordConn{}, &recordConn{}
	manager.AddClient("bob", bob, key, nil)
	database.SaveFriendRelationship("alice", "bob")
	group, _ := database.CreateGroup("Team", "alice", []string{"alice", "bob"})
	database.DB.Exec("DROP TABLE messages")
	content, _ := crypto.EncryptMessage("hello", key)
	handlePrivateChat(alice, "alice", key, map[string]interface{}{"to": "bob", "content": content, "request_id": "p"}, manager)
	handleGroupChat(alice, "alice", key, map[string]interface{}{"gid": group.GID, "content": content, "request_id": "g"}, manager)
	if len(bob.messages(t)) != 0 {
		t.Fatal("uncommitted message forwarded")
	}
	for kind, id := range map[string]string{"private_chat_result": "p", "group_chat_result": "g"} {
		result := alice.result(t, kind)
		if result["success"] != false || result["request_id"] != id {
			t.Fatalf("%v", result)
		}
	}
}

func TestRejectedChatAlwaysReturnsCorrelatedFailure(t *testing.T) {
	manager := setupHandlers(t)
	for _, request := range []map[string]interface{}{{"request_id": "invalid"}, {"request_id": "self", "to": "alice", "content": "bad"}, {"request_id": "stranger", "to": "bob", "content": "bad"}} {
		conn := &recordConn{}
		handlePrivateChat(conn, "alice", nil, request, manager)
		result := conn.result(t, "private_chat_result")
		if result["success"] != false || result["request_id"] != request["request_id"] {
			t.Fatalf("%v", result)
		}
	}
}

func TestOversizeForwardPacketRejectedBeforeSaving(t *testing.T) {
	manager := setupHandlers(t)
	database.SaveFriendRelationship("alice", "bob")
	key := []byte("0123456789abcdef")
	content, _ := crypto.EncryptMessage(strings.Repeat("a", protocol.MaxMessageLen), key)
	conn := &recordConn{}
	handlePrivateChat(conn, "alice", key, map[string]interface{}{"to": "bob", "content": content, "request_id": "large"}, manager)
	if conn.result(t, "private_chat_result")["success"] != false {
		t.Fatal("oversize message acknowledged")
	}
	var count int
	database.DB.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	if count != 0 {
		t.Fatal("undeliverable message saved")
	}
}

func TestInviteDeclineDeletesOnlyResponderAndCannotJoin(t *testing.T) {
	manager := setupHandlers(t)
	group, _ := database.CreateGroup("Team", "alice", []string{"alice"})
	pendingGroupJoins[group.GID] = map[string]groupInvitation{"bob": {Inviter: "alice", CreatedAt: time.Now()}, "carol": {Inviter: "alice", CreatedAt: time.Now()}}
	conn := &recordConn{}
	handleGroupInviteResponse(conn, "bob", map[string]interface{}{"gid": group.GID, "accepted": false})
	if conn.result(t, "group_invite_response_result")["success"] != true {
		t.Fatal("decline failed")
	}
	if _, exists := pendingGroupJoins[group.GID]["bob"]; exists {
		t.Fatal("declined invitation retained")
	}
	if _, exists := pendingGroupJoins[group.GID]["carol"]; !exists {
		t.Fatal("other user's invitation deleted")
	}
	handleGroupJoin(conn, "bob", map[string]interface{}{"gid": group.GID}, manager)
	if conn.result(t, "group_join_result")["success"] != false {
		t.Fatal("declined invite accepted")
	}
	replay := &recordConn{}
	SendPendingNotifications(replay, "bob")
	if len(replay.messages(t)) != 0 {
		t.Fatal("declined invitation replayed")
	}
}

func TestManagementActorHasOneResultAndRenameOldName(t *testing.T) {
	manager := setupHandlers(t)
	alice, bob := &recordConn{}, &recordConn{}
	manager.AddClient("alice", alice, nil, nil)
	manager.AddClient("bob", bob, nil, nil)
	group, _ := database.CreateGroup("Before", "alice", []string{"alice", "bob"})
	handleGroupRename(alice, "alice", map[string]interface{}{"gid": group.GID, "new_name": "After"}, manager)
	if len(alice.messages(t)) != 1 || alice.result(t, "group_rename_result")["old_name"] != "Before" {
		t.Fatal("duplicate or incorrect rename response")
	}
	if bob.result(t, "group_rename_notification")["new_name"] != "After" {
		t.Fatal("member not notified")
	}
	alice.data.Reset()
	handleGroupTransfer(alice, "alice", map[string]interface{}{"gid": group.GID, "new_owner": "bob"}, manager)
	if len(alice.messages(t)) != 1 || alice.messages(t)[0]["type"] != "group_transfer_result" {
		t.Fatal("duplicate transfer response")
	}
	bob.data.Reset()
	handleGroupDisband(bob, "bob", map[string]interface{}{"gid": group.GID}, manager)
	if len(bob.messages(t)) != 1 || bob.messages(t)[0]["type"] != "group_disband_result" {
		t.Fatal("duplicate disband response")
	}
}
