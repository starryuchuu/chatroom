package server

import (
	chatcrypto "chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"chatroom/internal/types"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setupServer(t *testing.T) {
	t.Helper()
	database.InitDB(filepath.Join(t.TempDir(), "chat.db"))
	t.Cleanup(func() { database.DB.Close() })
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	clientManager = NewClientManager()
	if err := database.RegisterUser("alice", "secret123"); err != nil {
		t.Fatal(err)
	}
}

func startPeer(t *testing.T, key []byte) (net.Conn, <-chan struct{}) {
	t.Helper()
	peer, remote := net.Pipe()
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	go func() { defer close(done); handleConnection(remote) }()
	t.Cleanup(func() {
		peer.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("connection handler leaked")
		}
	})
	public, err := protocol.RecvMsg(peer)
	if err != nil || public["type"] != "public_key" {
		t.Fatalf("handshake: %v %v", public, err)
	}
	encrypted, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &privateKey.PublicKey, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.SendMsg(peer, map[string]string{"type": "session_key", "key": base64.StdEncoding.EncodeToString(encrypted)}); err != nil {
		t.Fatal(err)
	}
	return peer, done
}

func loginPayload(t *testing.T, key []byte) map[string]string {
	t.Helper()
	info, _ := json.Marshal(map[string]string{"from": "alice", "password": "secret123"})
	encrypted, err := chatcrypto.EncryptMessage(string(info), key)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"type": "encrypted_login", "data": encrypted}
}

type concurrentAuthManager struct {
	types.ClientManager
	arrivals atomic.Int32
	gate     chan struct{}
}

func (m *concurrentAuthManager) IsUserOnline(string) bool {
	if m.arrivals.Add(1) == 2 {
		close(m.gate)
	}
	<-m.gate
	return false // Force both connections past the early, non-atomic precheck.
}

func TestConcurrentLoginOneSuccessPreservesFirstSession(t *testing.T) {
	setupServer(t)
	manager := &concurrentAuthManager{ClientManager: NewClientManager(), gate: make(chan struct{})}
	clientManager = manager
	key := make([]byte, 16)
	first, firstDone := startPeer(t, key)
	second, secondDone := startPeer(t, key)
	type outcome struct {
		peer net.Conn
		done <-chan struct{}
		msg  map[string]interface{}
		err  error
	}
	outcomes := make(chan outcome, 2)
	for _, item := range []outcome{{peer: first, done: firstDone}, {peer: second, done: secondDone}} {
		go func(item outcome) {
			err := protocol.SendMsg(item.peer, loginPayload(t, key))
			if err == nil {
				item.msg, err = protocol.RecvMsg(item.peer)
			}
			item.err = err
			outcomes <- item
		}(item)
	}
	successes := 0
	for i := 0; i < 2; i++ {
		item := <-outcomes
		if item.err != nil || item.msg["type"] != "login_result" {
			t.Fatalf("first response was not auth: %v %v", item.msg, item.err)
		}
		if item.msg["success"] == true {
			successes++
		} else {
			select {
			case <-item.done:
			case <-time.After(3 * time.Second):
				t.Fatal("losing login not closed")
			}
		}
	}
	if successes != 1 {
		t.Fatalf("got %d successful logins", successes)
	}
	if _, ok := manager.GetClient("alice"); !ok {
		t.Fatal("rejected duplicate removed winning session")
	}
}

func TestMalformedAuthDoesNotCreateEmptyUser(t *testing.T) {
	setupServer(t)
	peer, done := startPeer(t, make([]byte, 16))
	protocol.SendMsg(peer, map[string]string{"type": "encrypted_login"})
	msg, err := protocol.RecvMsg(peer)
	if err != nil || msg["success"] != false {
		t.Fatalf("%v %v", msg, err)
	}
	<-done
	if clientManager.IsUserOnline("") || len(clientManager.GetOnlineUsernames()) != 0 {
		t.Fatal("rejected auth created an online user")
	}
}

func TestInvalidAESKeyRejectedBeforeAuth(t *testing.T) {
	setupServer(t)
	peer, done := startPeer(t, make([]byte, 17))
	msg, err := protocol.RecvMsg(peer)
	if err != nil || msg["type"] != "error" {
		t.Fatalf("%v %v", msg, err)
	}
	<-done
}

func TestReservedLoginHiddenAndRemovalChecksConnection(t *testing.T) {
	cm := NewClientManager()
	first, p1 := net.Pipe()
	second, p2 := net.Pipe()
	defer first.Close()
	defer p1.Close()
	defer second.Close()
	defer p2.Close()
	if !cm.AddClient("alice", first, nil, nil) {
		t.Fatal("reservation failed")
	}
	if !cm.IsUserOnline("alice") {
		t.Fatal("reservation failed to reject duplicates")
	}
	if _, ok := cm.GetClient("alice"); ok {
		t.Fatal("unacknowledged login visible to senders")
	}
	if len(cm.GetOnlineUsernames()) != 0 {
		t.Fatal("unacknowledged login broadcast")
	}
	if cm.AddClient("alice", second, nil, nil) {
		t.Fatal("duplicate accepted")
	}
	cm.RemoveClient("alice", second)
	if !cm.ActivateClient("alice", first) {
		t.Fatal("duplicate removed reservation")
	}
	cm.RemoveClient("alice", second)
	if _, ok := cm.GetClient("alice"); !ok {
		t.Fatal("wrong connection removed online session")
	}
	cm.RemoveClient("alice", first)
	if cm.IsUserOnline("alice") {
		t.Fatal("owner cleanup failed")
	}
}

func TestSlowBroadcastDoesNotHoldManagerLock(t *testing.T) {
	cm := NewClientManager()
	peer, remote := net.Pipe()
	defer peer.Close()
	defer remote.Close()
	entered := make(chan struct{})
	cm.AddClient("alice", protocol.WrapConn(&signalWriteConn{Conn: remote, entered: entered}), nil, nil)
	reserved := cm.(*clientManagerImpl).clients["alice"].Conn
	cm.ActivateClient("alice", reserved)
	broadcastDone := make(chan struct{})
	go func() { cm.BroadcastMessage(map[string]interface{}{"type": "test"}); close(broadcastDone) }()
	<-entered
	removed := make(chan struct{})
	go func() { cm.RemoveClient("alice", reserved); close(removed) }()
	select {
	case <-removed:
	case <-time.After(time.Second):
		t.Fatal("broadcast held global manager lock during blocked write")
	}
	peer.Close()
	<-broadcastDone
}

type signalWriteConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *signalWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(p)
}
