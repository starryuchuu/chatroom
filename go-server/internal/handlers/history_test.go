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
