package handlers

import (
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"chatroom/internal/types"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

// Unlike recordManager, this manager hides reserved sessions until activation,
// matching the visibility guarantees of the server's real client manager.
type friendSnapshotManager struct {
	*recordManager
	mu         sync.Mutex
	onActivate func(net.Conn)
}

func (m *friendSnapshotManager) AddClient(name string, conn net.Conn, key []byte, friends map[string]struct{}) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recordManager.AddClient(name, conn, key, friends)
}

func (m *friendSnapshotManager) ActivateClient(name string, conn net.Conn) bool {
	m.mu.Lock()
	client, ok := m.clients[name]
	if !ok || client.Conn != conn {
		m.mu.Unlock()
		return false
	}
	client.Ready = true
	m.mu.Unlock()
	if m.onActivate != nil {
		m.onActivate(conn)
	}
	return true
}

func (m *friendSnapshotManager) GetClient(name string) (*types.ClientInfo, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	client, ok := m.clients[name]
	if !ok || !client.Ready {
		return nil, false
	}
	return client, true
}

func friendSnapshotPipe(t *testing.T) (net.Conn, *protocol.Conn) {
	t.Helper()
	peer, remote := net.Pipe()
	conn := protocol.WrapConn(remote)
	t.Cleanup(func() { peer.Close(); conn.Close() })
	if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	protocol.EnableQueuedWrites(conn)
	return peer, conn
}

func readFriendSnapshotMessage(t *testing.T, peer net.Conn) map[string]interface{} {
	t.Helper()
	msg, err := protocol.RecvMsg(peer)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func applyFriendSnapshotMessage(t *testing.T, friends map[string]struct{}, msg map[string]interface{}) map[string]struct{} {
	t.Helper()
	switch msg["type"] {
	case "friends_list":
		friends = make(map[string]struct{})
		for _, value := range msg["friends"].([]interface{}) {
			friends[value.(string)] = struct{}{}
		}
	case "friend_update":
		friends[msg["friend"].(string)] = struct{}{}
	}
	return friends
}

func TestFriendSnapshotRefreshesFriendsAcceptedBeforeActivation(t *testing.T) {
	manager := &friendSnapshotManager{recordManager: setupHandlers(t)}
	if err := database.SaveFriendRelationship("alice", "carol"); err != nil {
		t.Fatal(err)
	}
	handleFriendRequest(&recordConn{}, "alice", map[string]interface{}{"to": "bob"}, manager)
	staleFriends, err := database.LoadFriends("alice")
	if err != nil {
		t.Fatal(err)
	}
	peer, conn := friendSnapshotPipe(t)
	if !manager.AddClient("alice", conn, nil, staleFriends) {
		t.Fatal("could not reserve the logging-in session")
	}

	// The acceptance commits after the login's first database read, while Alice
	// is still hidden. No live update can reach Alice during this window.
	bob := &recordConn{}
	handleFriendResponse(bob, "bob", map[string]interface{}{"to": "alice", "accepted": true}, manager)
	bob.result(t, "friend_update")
	if _, visible := manager.GetClient("alice"); visible {
		t.Fatal("reserved login session was visible before activation")
	}
	if _, updated := staleFriends["bob"]; updated {
		t.Fatal("test did not preserve the stale login read")
	}

	if err := SendFriendsAndActivate(conn, "alice", manager); err != nil {
		t.Fatal(err)
	}
	msg := readFriendSnapshotMessage(t, peer)
	if msg["type"] != "friends_list" {
		t.Fatalf("first login snapshot was %v", msg)
	}
	got := applyFriendSnapshotMessage(t, nil, msg)
	want := map[string]struct{}{"bob": {}, "carol": {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("friend accepted during login was omitted: got %v, want %v", got, want)
	}
	if _, visible := manager.GetClient("alice"); !visible {
		t.Fatal("successful snapshot did not activate the session")
	}
}

func TestFriendSnapshotPrecedesTrafficAndAcceptanceAtActivation(t *testing.T) {
	manager := &friendSnapshotManager{recordManager: setupHandlers(t)}
	if err := database.SaveFriendRelationship("alice", "carol"); err != nil {
		t.Fatal(err)
	}
	handleFriendRequest(&recordConn{}, "alice", map[string]interface{}{"to": "bob"}, manager)
	peer, conn := friendSnapshotPipe(t)
	if !manager.AddClient("alice", conn, nil, nil) {
		t.Fatal("could not reserve the logging-in session")
	}

	activated := make(chan struct{})
	stop := make(chan struct{})
	accepted := make(chan struct{})
	bob := &recordConn{}
	var activationErr error
	manager.onActivate = func(conn net.Conn) {
		// Online traffic may enqueue immediately when the connection becomes
		// visible, even while its peer has not read any queued snapshot bytes.
		activationErr = protocol.SendMsg(conn, map[string]interface{}{"type": "online_users"})
		close(activated)
	}
	go func() {
		defer close(accepted)
		select {
		case <-activated:
			handleFriendResponse(bob, "bob", map[string]interface{}{"to": "alice", "accepted": true}, manager)
		case <-stop:
		}
	}()
	defer func() {
		close(stop)
		select {
		case <-accepted:
		case <-time.After(3 * time.Second):
			t.Error("concurrent friend acceptance did not finish")
		}
	}()

	if err := SendFriendsAndActivate(conn, "alice", manager); err != nil {
		t.Fatal(err)
	}
	if activationErr != nil {
		t.Fatal(activationErr)
	}
	var friends map[string]struct{}
	for i, kind := range []string{"friends_list", "online_users", "friend_response", "friend_update"} {
		msg := readFriendSnapshotMessage(t, peer)
		if msg["type"] != kind {
			t.Fatalf("frame %d: got %v, want %s; snapshot must precede publication", i, msg, kind)
		}
		friends = applyFriendSnapshotMessage(t, friends, msg)
	}
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("friend acceptance did not complete")
	}
	bob.result(t, "friend_update")
	persisted, err := database.LoadFriends("alice")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(friends, persisted) || len(friends) != 2 {
		t.Fatalf("snapshot and live update lost friends: client %v, database %v", friends, persisted)
	}
}

func TestFriendSnapshotFailureDoesNotActivateSession(t *testing.T) {
	for _, failure := range []string{"database", "closed connection"} {
		t.Run(failure, func(t *testing.T) {
			manager := &friendSnapshotManager{recordManager: setupHandlers(t)}
			_, conn := friendSnapshotPipe(t)
			if !manager.AddClient("alice", conn, nil, nil) {
				t.Fatal("could not reserve the logging-in session")
			}
			if failure == "database" {
				if _, err := database.DB.Exec("DROP TABLE friends"); err != nil {
					t.Fatal(err)
				}
			} else if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if err := SendFriendsAndActivate(conn, "alice", manager); err == nil {
				t.Fatal("failed snapshot returned success")
			}
			if _, visible := manager.GetClient("alice"); visible {
				t.Fatal("session became visible without a usable friend snapshot")
			}
		})
	}
}
