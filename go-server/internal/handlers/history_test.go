package handlers

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type blockedHistoryConn struct {
	recordConn
	entered, release chan struct{}
	blocked          bool
}

func TestHistoryErrorsIdentifyConversation(t *testing.T) {
	for _, kind := range []string{"private", "group"} {
		for _, failure := range []string{"validation", "authorization", "storage"} {
			t.Run(kind+"/"+failure, func(t *testing.T) {
				setupHandlers(t)
				target := "bob"
				if kind == "group" {
					members := []string{"bob"}
					if failure != "authorization" {
						members = append(members, "alice")
					}
					group, err := database.CreateGroup("Team", "bob", members)
					if err != nil {
						t.Fatal(err)
					}
					target = group.GID
				} else if failure != "authorization" {
					if err := database.SaveFriendRelationship("alice", "bob"); err != nil {
						t.Fatal(err)
					}
				}
				before := float64(2)
				if failure == "validation" {
					before = 0
				} else if failure == "storage" {
					if _, err := database.DB.Exec("DROP TABLE messages"); err != nil {
						t.Fatal(err)
					}
				}
				conn := &recordConn{}
				handleHistoryRequest(conn, "alice", make([]byte, 16), map[string]interface{}{
					"chat_type": kind, "target": target, "before_id": before, "request_id": "error-page",
				})
				response := conn.result(t, "history_error")
				if response["request_id"] != "error-page" {
					t.Fatal("history error lost request ID")
				}
				if response["history_kind"] != kind || response["history_target"] != target {
					t.Fatal("history error lost conversation scope")
				}
			})
		}
	}
}

func TestHistoryPageEchoesRequestIDOnControlsAndMessages(t *testing.T) {
	setupHandlers(t)
	if err := database.SaveFriendRelationship("alice", "bob"); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveMessage("private", "bob", "alice", "", "saved", "now"); err != nil {
		t.Fatal(err)
	}
	conn := &recordConn{}
	handleHistoryRequest(conn, "alice", make([]byte, 16), map[string]interface{}{
		"chat_type": "private", "target": "bob", "before_id": float64(2), "request_id": "page-界",
	})
	for _, kind := range []string{"history_begin", "history_end", "private_chat"} {
		field := "request_id"
		if kind == "private_chat" {
			field = "history_request_id"
		}
		if conn.result(t, kind)[field] != "page-界" {
			t.Fatal("page lost request correlation: " + kind)
		}
	}
}

func TestHistoryRequestIDValidationAndUnicodeLength(t *testing.T) {
	cases := []struct {
		name  string
		id    interface{}
		valid bool
	}{
		{"null", nil, false}, {"number", float64(1), false}, {"boolean", true, false},
		{"empty", "", false}, {"array", []interface{}{}, false},
		{"too-long", strings.Repeat("a", 129), false},
		{"invalid-utf8", string([]byte{0xff}), false},
		{"ascii-limit", strings.Repeat("a", 128), true},
		{"unicode-limit", strings.Repeat("界", 128), true},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			setupHandlers(t)
			if err := database.SaveFriendRelationship("alice", "bob"); err != nil {
				t.Fatal(err)
			}
			conn := &recordConn{}
			handleHistoryRequest(conn, "alice", make([]byte, 16), map[string]interface{}{
				"chat_type": "private", "target": "bob", "before_id": float64(2), "request_id": item.id,
			})
			if item.valid {
				if conn.result(t, "history_end")["request_id"] != item.id {
					t.Fatal("valid request ID did not round-trip")
				}
			} else {
				reply := conn.result(t, "history_error")
				if !strings.Contains(reply["error"].(string), "参数") || reply["request_id"] != nil {
					t.Fatal("invalid request ID was accepted or echoed")
				}
			}
		})
	}
}

func (c *blockedHistoryConn) Write(frame []byte) (int, error) {
	var msg map[string]interface{}
	json.Unmarshal(frame[4:], &msg)
	if msg["type"] == "group_chat" && !c.blocked {
		c.blocked = true
		close(c.entered)
		<-c.release
	}
	return c.recordConn.Write(frame)
}
func TestHistoryEnqueueSharesMembershipOperationLock(t *testing.T) {
	setupHandlers(t)
	group, err := database.CreateGroup("Team", "alice", []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	database.SaveMessage("group", "alice", "", group.GID, "first", "now")
	database.SaveMessage("group", "alice", "", group.GID, "second", "now")
	conn := &blockedHistoryConn{entered: make(chan struct{}), release: make(chan struct{})}
	historyDone := make(chan error, 1)
	go func() { historyDone <- SendHistory(conn, "bob", make([]byte, 16), "", "", 0) }()
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("history never reached group packet")
	}
	removed := make(chan struct{})
	go func() {
		unlock := LockGroup(group.GID)
		defer unlock()
		database.UpdateGroupMembers(group.GID, []string{"alice"})
		close(removed)
	}()
	select {
	case <-removed:
		close(conn.release)
		t.Fatal("membership removal bypassed history enqueue lock")
	case <-time.After(30 * time.Millisecond):
	}
	close(conn.release)
	if err = <-historyDone; err != nil {
		t.Fatal(err)
	}
	<-removed
	fresh := &recordConn{}
	if err = SendHistory(fresh, "bob", make([]byte, 16), "group", group.GID, 0); err != nil {
		t.Fatal(err)
	}
	for _, msg := range fresh.messages(t) {
		if msg["type"] == "group_chat" {
			t.Fatal("removed member received later history")
		}
	}
}

func TestLargeUnicodeGroupSnapshotChunksRoundtrip(t *testing.T) {
	setupHandlers(t)
	name := strings.Repeat("名字", 300000)
	group, err := database.CreateGroup(name, "alice", []string{"alice"})
	if err != nil {
		t.Fatal(err)
	}
	conn := &recordConn{}
	if err = SendUserGroups(conn, "alice"); err != nil {
		t.Fatal(err)
	}
	var joined strings.Builder
	messages := conn.messages(t)
	if len(messages) < 2 {
		t.Fatal("oversize snapshot was not chunked")
	}
	for _, msg := range messages {
		if msg["type"] != "user_groups_chunk" {
			t.Fatalf("unexpected %v", msg["type"])
		}
		joined.WriteString(msg["data"].(string))
	}
	var snapshot struct {
		Groups []struct {
			GID  string `json:"gid"`
			Name string `json:"group_name"`
		} `json:"groups"`
	}
	if err = json.Unmarshal([]byte(joined.String()), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Groups) != 1 || snapshot.Groups[0].Name != name || snapshot.Groups[0].GID != group.GID {
		t.Fatal("UTF-8 snapshot corrupted")
	}
}

func TestJoiningGroupImmediatelyReceivesDurableHistory(t *testing.T) {
	manager := setupHandlers(t)
	group, err := database.CreateGroup("Team", "alice", []string{"alice"})
	if err != nil {
		t.Fatal(err)
	}
	database.SaveMessage("group", "alice", "", group.GID, "before join", "now")
	key := make([]byte, 16)
	bob := &recordConn{}
	manager.AddClient("bob", bob, key, nil)
	pendingGroupJoins[group.GID] = map[string]groupInvitation{"bob": {Inviter: "alice", CreatedAt: time.Now()}}
	handleGroupJoin(bob, "bob", map[string]interface{}{"gid": group.GID}, manager)
	msg := bob.result(t, "group_chat")
	plain, err := crypto.DecryptMessage(msg["content"].(string), key)
	if err != nil || plain != "before join" {
		t.Fatalf("missing group history: %s %v", plain, err)
	}
}

func TestCongestedHistoryWaitsOutsideMembershipLock(t *testing.T) {
	setupHandlers(t)
	group, err := database.CreateGroup("Team", "alice", []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	blocked := &blockedHistoryConn{entered: make(chan struct{}), release: make(chan struct{})}
	conn := protocol.WrapConn(blocked)
	protocol.EnableQueuedWrites(conn)
	defer conn.Close()
	if err = protocol.SendMsg(conn, map[string]interface{}{"type": "group_chat"}); err != nil {
		t.Fatal(err)
	}
	<-blocked.entered
	defer close(blocked.release)
	for i := 0; i < 256; i++ {
		if err = protocol.SendMsg(conn, map[string]interface{}{"type": "padding"}); err != nil {
			t.Fatal(err)
		}
	}
	result := make(chan error, 1)
	go func() {
		result <- sendAuthorizedGroupHistory(conn, "bob", group.GID, map[string]interface{}{"type": "group_chat", "gid": group.GID})
	}()
	time.Sleep(20 * time.Millisecond)
	removed := make(chan error, 1)
	go func() {
		unlock := LockGroup(group.GID)
		defer unlock()
		removed <- database.UpdateGroupMembers(group.GID, []string{"alice"})
	}()
	select {
	case err = <-removed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queue backpressure held the membership lock")
	}
	select {
	case err = <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("history retry failed to recheck removed member")
	}
}
