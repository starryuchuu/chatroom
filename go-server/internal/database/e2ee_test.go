package database

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestE2EEIdentityPublicationIsImmutableAndEncrypted(t *testing.T) {
	t.Setenv("CHATROOM_STORAGE_KEY_FILE", "")
	path := filepath.Join(t.TempDir(), "chat.db")
	if err := OpenDB(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { DB.Close() })
	const alice = "alice-identity-secret"
	const first = `{"exchange":"public-exchange-secret","sign":"public-sign-secret","v":1}`
	if missing, err := GetE2EEIdentity(alice); err != nil || missing != "" {
		t.Fatalf("unpublished identity: %q %v", missing, err)
	}
	for i := 0; i < 2; i++ {
		if actual, err := PublishE2EEIdentity(alice, first); err != nil || actual != first {
			t.Fatalf("publish/confirm identity: %q %v", actual, err)
		}
	}
	if actual, err := PublishE2EEIdentity(alice, `{"sign":"replacement"}`); err == nil || actual != first {
		t.Fatalf("identity replacement accepted: %q %v", actual, err)
	}
	if actual, err := GetE2EEIdentity(alice); err != nil || actual != first {
		t.Fatalf("identity changed: %q %v", actual, err)
	}
	var name, encoded string
	if err := DB.QueryRow("SELECT username,identity FROM e2ee_identities").Scan(&name, &encoded); err != nil {
		t.Fatal(err)
	}
	if name != storage.token(alice) || encoded == first {
		t.Fatal("identity was stored without the existing privacy protections")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{alice, "public-exchange-secret", "public-sign-secret"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("plaintext identity metadata remains in the database")
		}
	}
	DB.Close()
	if err = OpenDB(path); err != nil {
		t.Fatal(err)
	}
	if actual, err := GetE2EEIdentity(alice); err != nil || actual != first {
		t.Fatalf("reopen lost public identity: %q %v", actual, err)
	}
}

func TestConcurrentE2EEIdentityPublicationHasOneWinner(t *testing.T) {
	t.Setenv("CHATROOM_STORAGE_KEY_FILE", "")
	if err := OpenDB(filepath.Join(t.TempDir(), "chat.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { DB.Close() })
	type result struct {
		identity string
		err      error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var workers sync.WaitGroup
	for _, identity := range []string{`{"sign":"first"}`, `{"sign":"second"}`} {
		workers.Add(1)
		go func(identity string) {
			defer workers.Done()
			<-start
			actual, err := PublishE2EEIdentity("alice", identity)
			results <- result{actual, err}
		}(identity)
	}
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	winner, err := GetE2EEIdentity("alice")
	if err != nil {
		t.Fatal(err)
	}
	for result := range results {
		if result.err == nil {
			successes++
		}
		if result.identity != winner {
			t.Fatal("concurrent publisher did not observe the immutable winner")
		}
	}
	if successes != 1 {
		t.Fatalf("successful competing identities: %d", successes)
	}
	var count int
	if err = DB.QueryRow("SELECT COUNT(*) FROM e2ee_identities").Scan(&count); err != nil || count != 1 {
		t.Fatalf("identity rows: %d %v", count, err)
	}
}

func TestE2EEIdentityStorageBindsTheAccount(t *testing.T) {
	t.Setenv("CHATROOM_STORAGE_KEY_FILE", "")
	if err := OpenDB(filepath.Join(t.TempDir(), "chat.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { DB.Close() })
	if _, err := PublishE2EEIdentity("alice", `{"sign":"alice"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishE2EEIdentity("bob", `{"sign":"bob"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec("UPDATE e2ee_identities SET identity=(SELECT identity FROM e2ee_identities WHERE username=?) WHERE username=?", storage.token("bob"), storage.token("alice")); err != nil {
		t.Fatal(err)
	}
	if _, err := GetE2EEIdentity("alice"); err == nil {
		t.Fatal("identity ciphertext moved to another account was accepted")
	}
}

func TestE2EEMessageFlagsSurviveBackwardForwardHistoryAndReopen(t *testing.T) {
	t.Setenv("CHATROOM_STORAGE_KEY_FILE", "")
	path := filepath.Join(t.TempDir(), "chat.db")
	if err := OpenDB(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { DB.Close() })
	if err := SaveFriendRelationship("alice", "bob"); err != nil {
		t.Fatal(err)
	}
	const envelope = `{"body":"only-ciphertext","signature":"opaque-signature"}`
	first, err := SaveMessageWithID("private", "bob", "alice", "", "legacy message", "then")
	if err != nil {
		t.Fatal(err)
	}
	last, err := SaveE2EEMessageWithID("private", "alice", "bob", "", envelope, "now")
	if err != nil {
		t.Fatal(err)
	}
	var encoded string
	var flag int
	if err = DB.QueryRow("SELECT message,e2ee FROM messages WHERE id=?", last).Scan(&encoded, &flag); err != nil || encoded == envelope || flag != 1 {
		t.Fatalf("E2EE envelope storage: %q %d %v", encoded, flag, err)
	}
	DB.Close()
	if err = OpenDB(path); err != nil {
		t.Fatal(err)
	}
	backward, more, err := GetHistoryPage("alice", last, 0, "private", "bob")
	if err != nil || more || len(backward) != 2 || backward[0].ID != first || backward[0].E2EE || !backward[1].E2EE || backward[1].Content != envelope {
		t.Fatalf("backward history: %+v %v %v", backward, more, err)
	}
	forward, more, err := GetSyncPage("bob", last, 0)
	if err != nil || more || len(forward) != 2 || forward[0].E2EE || !forward[1].E2EE || forward[1].Content != envelope {
		t.Fatalf("forward history: %+v %v %v", forward, more, err)
	}
}

func TestE2EESchemaUpgradeRetainsLegacyRowsAndChecksKeyFirst(t *testing.T) {
	t.Setenv("CHATROOM_STORAGE_KEY_FILE", "")
	path := filepath.Join(t.TempDir(), "chat.db")
	if err := OpenDB(path); err != nil {
		t.Fatal(err)
	}
	if err := SaveFriendRelationship("alice", "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveMessageWithID("private", "bob", "alice", "", "legacy row", "then"); err != nil {
		t.Fatal(err)
	}
	// Reconstruct the schema written by v1.1.0 without changing its encrypted
	// fields or the storage-v1 key check.
	if _, err := DB.Exec("ALTER TABLE messages DROP COLUMN e2ee"); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec("DROP TABLE e2ee_identities"); err != nil {
		t.Fatal(err)
	}
	DB.Close()
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(path + ".key")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".key", bytes.Repeat([]byte{42}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if err = OpenDB(path); err == nil {
		t.Fatal("wrong storage key accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("failed key validation changed the legacy database")
	}
	if err = os.WriteFile(path+".key", key, 0600); err != nil {
		t.Fatal(err)
	}
	if err = OpenDB(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { DB.Close() })
	history, err := GetChatHistory("alice")
	if err != nil || len(history) != 1 || history[0].E2EE || history[0].Content != "legacy row" {
		t.Fatalf("legacy upgrade lost history: %+v %v", history, err)
	}
	if _, err = PublishE2EEIdentity("alice", `{"sign":"upgraded"}`); err != nil {
		t.Fatal("legacy database did not gain the identity directory", err)
	}
}
