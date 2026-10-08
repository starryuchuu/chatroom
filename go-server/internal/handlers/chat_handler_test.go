package handlers

import (
	"bytes"
	"chatroom/internal/database"
	"chatroom/internal/types"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type recordConn struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (c *recordConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *recordConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.Write(p)
}
func (*recordConn) Close() error                     { return nil }
func (*recordConn) LocalAddr() net.Addr              { return nil }
func (*recordConn) RemoteAddr() net.Addr             { return nil }
func (*recordConn) SetDeadline(time.Time) error      { return nil }
func (*recordConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordConn) messages(t *testing.T) []map[string]interface{} {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	reader := bytes.NewReader(c.data.Bytes())
	var result []map[string]interface{}
	for reader.Len() > 0 {
		var size uint32
		if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
			t.Fatal(err)
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(reader, body); err != nil {
			t.Fatal(err)
		}
		var msg map[string]interface{}
		if err := json.Unmarshal(body, &msg); err != nil {
			t.Fatal(err)
		}
		result = append(result, msg)
	}
	return result
}
func (c *recordConn) result(t *testing.T, kind string) map[string]interface{} {
	t.Helper()
	for _, msg := range c.messages(t) {
		if msg["type"] == kind {
			return msg
		}
	}
	t.Fatalf("missing %s", kind)
	return nil
}

type recordManager struct{ clients map[string]*types.ClientInfo }

func (m *recordManager) AddClient(name string, conn net.Conn, key []byte, friends map[string]struct{}) bool {
	if m.IsUserOnline(name) {
		return false
	}
	m.clients[name] = &types.ClientInfo{Conn: conn, Username: name, SessionKey: key, Friends: friends}
	return true
}
func (m *recordManager) ActivateClient(name string, conn net.Conn) bool {
	c, ok := m.clients[name]
	return ok && c.Conn == conn
}
func (m *recordManager) RemoveClient(name string, conn net.Conn) {
	if c, ok := m.clients[name]; ok && c.Conn == conn {
		delete(m.clients, name)
	}
}
func (m *recordManager) GetClient(name string) (*types.ClientInfo, bool) {
	c, ok := m.clients[name]
	return c, ok
}
func (m *recordManager) GetOnlineUsernames() []string {
	var names []string
	for n := range m.clients {
		names = append(names, n)
	}
	return names
}
func (*recordManager) BroadcastMessage(map[string]interface{}) {}
func (m *recordManager) IsUserOnline(name string) bool         { _, ok := m.clients[name]; return ok }

func setupHandlers(t *testing.T) *recordManager {
	t.Helper()
	database.InitDB(filepath.Join(t.TempDir(), "chat.db"))
	database.DB.SetMaxOpenConns(1)
	t.Cleanup(func() { database.DB.Close() })
	pendingFriendRequests = make(map[string]map[string]time.Time)
	pendingGroupJoins = make(map[string]map[string]groupInvitation)
	for _, name := range []string{"alice", "bob", "carol"} {
		if _, err := database.DB.Exec("INSERT INTO users(username,password) VALUES(?,?)", name, "unused"); err != nil {
			t.Fatal(err)
		}
	}
	return &recordManager{clients: make(map[string]*types.ClientInfo)}
}

func TestCreateGroupChecksFriendsAndDeduplicates(t *testing.T) {
	manager := setupHandlers(t)
	rejected := &recordConn{}
	handleGroupCreate(rejected, "alice", map[string]interface{}{"group_name": "Team", "members": []interface{}{"carol"}}, manager)
	if rejected.result(t, "group_create_result")["success"] != false {
		t.Fatal("nonfriend silently added to group")
	}
	var count int
	database.DB.QueryRow("SELECT COUNT(*) FROM groups").Scan(&count)
	if count != 0 {
		t.Fatal("unauthorized group created")
	}
	if err := database.SaveFriendRelationship("alice", "bob"); err != nil {
		t.Fatal(err)
	}
	owner := &recordConn{}
	manager.AddClient("alice", owner, nil, nil)
	handleGroupCreate(owner, "alice", map[string]interface{}{"group_name": "Team", "members": []interface{}{"bob", "bob", "alice"}}, manager)
	msg := owner.result(t, "group_create_result")
	if msg["success"] != true {
		t.Fatal(msg)
	}
	group, err := database.GetGroup(msg["gid"].(string))
	if err != nil || len(group.Members) != 2 {
		t.Fatalf("duplicate members: %v %v", group, err)
	}
}

func TestOfflineRequestsReplayAndCanBeAccepted(t *testing.T) {
	manager := setupHandlers(t)
	alice, bob := &recordConn{}, &recordConn{}
	handleFriendRequest(alice, "alice", map[string]interface{}{"to": "bob"}, manager)
	if alice.result(t, "friend_request_result")["success"] != true {
		t.Fatal("offline request rejected but blocks retries")
	}
	SendPendingNotifications(bob, "bob")
	if bob.result(t, "friend_request")["from"] != "alice" {
		t.Fatal("offline request not replayed")
	}
	handleFriendResponse(bob, "bob", map[string]interface{}{"to": "alice", "accepted": true}, manager)
	friends, err := database.AreFriends("alice", "bob")
	if err != nil || !friends {
		t.Fatal("acceptance not persisted")
	}
	if len(pendingFriendRequests) != 0 {
		t.Fatal("handled requester bucket leaked")
	}
}

func TestOfflineGroupInviteReplayAndJoin(t *testing.T) {
	manager := setupHandlers(t)
	database.SaveFriendRelationship("alice", "bob")
	group, err := database.CreateGroup("Team", "alice", []string{"alice"})
	if err != nil {
		t.Fatal(err)
	}
	alice, bob := &recordConn{}, &recordConn{}
	handleGroupInvite(alice, "alice", map[string]interface{}{"gid": group.GID, "to": "bob"}, manager)
	if alice.result(t, "group_invite_result")["success"] != true {
		t.Fatal("offline invitation rejected")
	}
	SendPendingNotifications(bob, "bob")
	bob.result(t, "group_invite")
	handleGroupJoin(bob, "bob", map[string]interface{}{"gid": group.GID}, manager)
	if bob.result(t, "group_join_result")["success"] != true {
		t.Fatal("replayed invite cannot be accepted")
	}
	if len(pendingGroupJoins) != 0 {
		t.Fatal("consumed invitation bucket leaked")
	}
}

func TestExpiredRequestsAreRemoved(t *testing.T) {
	setupHandlers(t)
	old := time.Now().Add(-25 * time.Hour)
	pendingFriendRequests["alice"] = map[string]time.Time{"bob": old}
	pendingGroupJoins["gone"] = map[string]groupInvitation{"bob": {Inviter: "alice", CreatedAt: old}}
	conn := &recordConn{}
	SendPendingNotifications(conn, "bob")
	if len(conn.messages(t)) != 0 || len(pendingFriendRequests) != 0 || len(pendingGroupJoins) != 0 {
		t.Fatal("expired requests retained/replayed")
	}
}

func TestFriendSaveFailureKeepsRequestAndDoesNotAcknowledge(t *testing.T) {
	manager := setupHandlers(t)
	alice, bob := &recordConn{}, &recordConn{}
	manager.AddClient("alice", alice, nil, nil)
	pendingFriendRequests["alice"] = map[string]time.Time{"bob": time.Now()}
	if _, err := database.DB.Exec("DROP TABLE friends"); err != nil {
		t.Fatal(err)
	}
	handleFriendResponse(bob, "bob", map[string]interface{}{"to": "alice", "accepted": true}, manager)
	if bob.result(t, "friend_response_result")["success"] != false {
		t.Fatal("database failure not reported")
	}
	if len(alice.messages(t)) != 0 {
		t.Fatal("sender received acceptance before database commit")
	}
	if _, ok := pendingFriendRequests["alice"]["bob"]; !ok {
		t.Fatal("failed acceptance consumed retryable request")
	}
}

func TestConcurrentJoinsKeepAllMembers(t *testing.T) {
	manager := setupHandlers(t)
	group, err := database.CreateGroup("Team", "alice", []string{"alice"})
	if err != nil {
		t.Fatal(err)
	}
	const count = 20
	pendingGroupJoins[group.GID] = make(map[string]groupInvitation)
	for i := 0; i < count; i++ {
		pendingGroupJoins[group.GID][fmt.Sprintf("member%d", i)] = groupInvitation{Inviter: "alice", CreatedAt: time.Now()}
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			conn := &recordConn{}
			handleGroupJoin(conn, fmt.Sprintf("member%d", i), map[string]interface{}{"gid": group.GID}, manager)
			if conn.result(t, "group_join_result")["success"] != true {
				t.Error("join failed")
			}
		}(i)
	}
	close(start)
	wg.Wait()
	updated, err := database.GetGroup(group.GID)
	if err != nil || len(updated.Members) != count+1 {
		t.Fatalf("concurrent joins lost members: %v %v", updated, err)
	}
	if len(groupLocks) != 0 {
		t.Fatal("per-group operation locks leaked")
	}
}

func TestTransferAndNewOwnerLeaveCannotBreakOwnership(t *testing.T) {
	manager := setupHandlers(t)
	for i := 0; i < 20; i++ {
		group, err := database.CreateGroup("Team", "alice", []string{"alice", "bob"})
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			handleGroupTransfer(&recordConn{}, "alice", map[string]interface{}{"gid": group.GID, "new_owner": "bob"}, manager)
		}()
		go func() {
			defer wg.Done()
			<-start
			handleGroupLeave(&recordConn{}, "bob", map[string]interface{}{"gid": group.GID}, manager)
		}()
		close(start)
		wg.Wait()
		updated, err := database.GetGroup(group.GID)
		if err != nil {
			t.Fatal(err)
		}
		present := false
		for _, member := range updated.Members {
			if member == updated.Owner {
				present = true
			}
		}
		if !present {
			t.Fatalf("owner left members during concurrent transfer: %+v", updated)
		}
	}
}

func TestDisbandClearsInvitations(t *testing.T) {
	manager := setupHandlers(t)
	group, err := database.CreateGroup("Team", "alice", []string{"alice"})
	if err != nil {
		t.Fatal(err)
	}
	pendingGroupJoins[group.GID] = map[string]groupInvitation{"bob": {Inviter: "alice", CreatedAt: time.Now()}}
	conn := &recordConn{}
	handleGroupDisband(conn, "alice", map[string]interface{}{"gid": group.GID}, manager)
	if conn.result(t, "group_disband_result")["success"] != true {
		t.Fatal("disband failed")
	}
	if _, ok := pendingGroupJoins[group.GID]; ok {
		t.Fatal("disbanded group's invitations leaked")
	}
}
