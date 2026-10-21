package handlers

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/e2ee"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func e2eeTestBundle(seed byte) (map[string]interface{}, ed25519.PrivateKey) {
	seedBytes := make([]byte, 32)
	for index := range seedBytes {
		seedBytes[index] = seed + byte(index)
	}
	private := ed25519.NewKeyFromSeed(seedBytes)
	exchange, _ := ecdh.X25519().NewPrivateKey(seedBytes)
	return map[string]interface{}{"v": 1, "sign": base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), "exchange": base64.StdEncoding.EncodeToString(exchange.PublicKey().Bytes())}, private
}

func publishTestIdentity(t *testing.T, username string, bundle map[string]interface{}, private ed25519.PrivateKey) {
	t.Helper()
	sign, _ := base64.StdEncoding.DecodeString(bundle["sign"].(string))
	exchange, _ := base64.StdEncoding.DecodeString(bundle["exchange"].(string))
	message := append([]byte("chatroom-e2ee-key-v1\x00"+username+"\x00"), sign...)
	message = append(message, exchange...)
	conn := &recordConn{}
	handleE2EEIdentityPublish(conn, username, map[string]interface{}{"request_id": "publish", "identity": bundle, "proof": base64.StdEncoding.EncodeToString(ed25519.Sign(private, message))})
	if result := conn.result(t, "e2ee_identity_result"); result["success"] != true {
		t.Fatalf("publish failed: %v", result)
	}
}

func signedTestMessage(t *testing.T, sender, kind, target string, identities map[string]map[string]interface{}, private ed25519.PrivateKey) map[string]interface{} {
	t.Helper()
	recipients := make(map[string]interface{}, len(identities))
	keys := make(map[string]interface{}, len(identities))
	for username, identity := range identities {
		recipients[username], _ = e2ee.Fingerprint(identity)
		keys[username] = base64.StdEncoding.EncodeToString(make([]byte, 60))
	}
	envelope := map[string]interface{}{"v": 1, "id": strings.Repeat("a", 32), "kind": kind, "sender": sender, "target": target, "sender_key": identities[sender], "recipients": recipients, "keys": keys, "ephemeral": identities[sender]["exchange"], "nonce": base64.StdEncoding.EncodeToString(make([]byte, 12)), "body": base64.StdEncoding.EncodeToString(make([]byte, 32))}
	canonical, err := e2ee.Canonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte("chatroom-e2ee-envelope-v1\x00"), canonical...)))
	return envelope
}

func TestE2EEPublicDirectoryAndDowngradeProtection(t *testing.T) {
	manager := setupHandlers(t)
	database.SaveFriendRelationship("alice", "bob")
	aliceBundle, alicePrivate := e2eeTestBundle(1)
	publishTestIdentity(t, "alice", aliceBundle, alicePrivate)
	publishTestIdentity(t, "alice", aliceBundle, alicePrivate)
	directory := &recordConn{}
	handleE2EEKeysRequest(directory, "alice", map[string]interface{}{"request_id": "keys", "kind": "private", "target": "bob"})
	reply := directory.result(t, "e2ee_keys")
	if reply["success"] != true || !reflect.DeepEqual(reply["missing"], []interface{}{"bob"}) {
		t.Fatalf("missing identities not explicit: %v", reply)
	}
	stranger := &recordConn{}
	handleE2EEKeysRequest(stranger, "carol", map[string]interface{}{"request_id": "private", "kind": "private", "target": "alice"})
	if stranger.result(t, "e2ee_keys")["success"] != false {
		t.Fatal("private directory exposed to stranger")
	}
	key := make([]byte, 16)
	content, _ := crypto.EncryptMessage("must not downgrade", key)
	for _, direction := range [][2]string{{"alice", "bob"}, {"bob", "alice"}} {
		conn := &recordConn{}
		handlePrivateChat(conn, direction[0], key, map[string]interface{}{"to": direction[1], "content": content, "request_id": "legacy"}, manager)
		if conn.result(t, "private_chat_result")["success"] != false {
			t.Fatal("E2EE silently downgraded to server-readable content")
		}
	}
	var count int
	database.DB.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	if count != 0 {
		t.Fatal("downgraded message persisted")
	}
}

func TestE2EEPrivateCiphertextStaysUnchangedAcrossLiveHistoryAndSync(t *testing.T) {
	manager := setupHandlers(t)
	database.SaveFriendRelationship("alice", "bob")
	aliceBundle, alicePrivate := e2eeTestBundle(1)
	bobBundle, bobPrivate := e2eeTestBundle(2)
	publishTestIdentity(t, "alice", aliceBundle, alicePrivate)
	publishTestIdentity(t, "bob", bobBundle, bobPrivate)
	alice, bob := &recordConn{}, &recordConn{}
	manager.AddClient("alice", alice, nil, nil)
	manager.AddClient("bob", bob, nil, nil)
	envelope := signedTestMessage(t, "alice", "private", "bob", map[string]map[string]interface{}{"alice": aliceBundle, "bob": bobBundle}, alicePrivate)
	handlePrivateChat(alice, "alice", nil, map[string]interface{}{"to": "bob", "e2ee": envelope, "request_id": "opaque"}, manager)
	if alice.result(t, "private_chat_result")["success"] != true {
		t.Fatal("valid signed envelope rejected")
	}
	history := &recordConn{}
	if err := SendHistory(history, "bob", nil, "private", "alice", 0); err != nil {
		t.Fatal(err)
	}
	sync := &recordConn{}
	handleSyncRequest(sync, "bob", nil, map[string]interface{}{"request_id": "sync", "after_id": float64(0)})
	expectedJSON, _ := json.Marshal(envelope)
	var expected map[string]interface{}
	json.Unmarshal(expectedJSON, &expected)
	for _, conn := range []*recordConn{alice, bob, history, sync} {
		message := conn.result(t, "private_chat")
		if !reflect.DeepEqual(message["e2ee"], expected) || message["content"] != nil || message["encryption"] != "e2ee_v1" {
			t.Fatalf("server rewrote or decrypted E2EE: %v", message)
		}
	}
	if history.result(t, "private_chat")["history"] != true || sync.result(t, "private_chat")["sync"] != true {
		t.Fatal("E2EE replay markers missing")
	}
	stored, _, err := database.GetChatHistorySnapshot("bob")
	if err != nil || len(stored) != 1 || !stored[0].E2EE {
		t.Fatalf("missing stored discriminator: %v %v", stored, err)
	}
}

func TestE2EEGroupRequiresExactCurrentRecipientsAndRejectsMixedFrames(t *testing.T) {
	manager := setupHandlers(t)
	aliceBundle, alicePrivate := e2eeTestBundle(1)
	bobBundle, bobPrivate := e2eeTestBundle(2)
	publishTestIdentity(t, "alice", aliceBundle, alicePrivate)
	publishTestIdentity(t, "bob", bobBundle, bobPrivate)
	group, _ := database.CreateGroup("Encrypted", "alice", []string{"alice", "bob"})
	identities := map[string]map[string]interface{}{"alice": aliceBundle, "bob": bobBundle}
	envelope := signedTestMessage(t, "alice", "group", group.GID, identities, alicePrivate)
	mixed := &recordConn{}
	handleGroupChat(mixed, "alice", nil, map[string]interface{}{"gid": group.GID, "e2ee": envelope, "content": nil}, manager)
	if mixed.result(t, "group_chat_result")["success"] != false {
		t.Fatal("mixed E2EE/legacy payload accepted")
	}
	valid := &recordConn{}
	handleGroupChat(valid, "alice", nil, map[string]interface{}{"gid": group.GID, "e2ee": envelope}, manager)
	if valid.result(t, "group_chat_result")["success"] != true {
		t.Fatal("valid group envelope rejected")
	}
	database.UpdateGroupMembers(group.GID, []string{"alice"})
	stale := &recordConn{}
	handleGroupChat(stale, "alice", nil, map[string]interface{}{"gid": group.GID, "e2ee": envelope}, manager)
	if stale.result(t, "group_chat_result")["success"] != false {
		t.Fatal("removed member retained future wrapped keys")
	}
	removed := &recordConn{}
	handleE2EEKeysRequest(removed, "bob", map[string]interface{}{"request_id": "keys", "kind": "group", "target": group.GID})
	if removed.result(t, "e2ee_keys")["success"] != false {
		t.Fatal("removed member fetched current recipients")
	}
	var count int
	database.DB.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	if count != 1 {
		t.Fatalf("invalid envelopes persisted: %d", count)
	}
}
