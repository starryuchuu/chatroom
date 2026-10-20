package database

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func legacyStorageFixture(t *testing.T, path string) {
	t.Helper()
	var err error
	DB, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err = createTables(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice-secret-name", "bob-secret-name", "carol-secret-name"} {
		hash, err := hashPassword("legacy password")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DB.Exec("INSERT INTO users(username,password) VALUES(?,?)", name, hash); err != nil {
			t.Fatal(err)
		}
	}
	statements := []string{
		"INSERT INTO friends VALUES('alice-secret-name','bob-secret-name')",
		"INSERT INTO friends VALUES('bob-secret-name','alice-secret-name')",
		"INSERT INTO messages VALUES(1,'private','bob-secret-name','alice-secret-name',NULL,'uniquely-secret-message','secret-date')",
		`INSERT INTO groups VALUES('g','uniquely-secret-group','alice-secret-name','["alice-secret-name","bob-secret-name"]','secret-date')`,
	}
	for _, stmt := range statements {
		if _, err = DB.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = DB.Exec("INSERT INTO pending_friend_requests VALUES(?,?,?)", "carol-secret-name", "alice-secret-name", float64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	if _, err = DB.Exec("INSERT INTO pending_group_invites VALUES(?,?,?,?)", "g", "bob-secret-name", "alice-secret-name", float64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	DB.Close()
}
func TestStorageMigrationConfidentialityAndReopen(t *testing.T) {
	t.Setenv("CHATROOM_STORAGE_KEY_FILE", "")
	path := filepath.Join(t.TempDir(), "chat.db")
	legacyStorageFixture(t, path)
	if err := OpenDB(path); err != nil {
		t.Fatal(err)
	}
	defer func() { DB.Close() }()
	ok, err := ValidateUser("alice-secret-name", "legacy password")
	if err != nil || !ok {
		t.Fatalf("login: %v %v", ok, err)
	}
	history, err := GetChatHistory("alice-secret-name")
	if err != nil || len(history) != 1 || history[0].Content != "uniquely-secret-message" || history[0].FromUser != "bob-secret-name" {
		t.Fatalf("history: %v %v", history, err)
	}
	groups, err := GetUserGroups("alice-secret-name")
	if err != nil || len(groups) != 1 || groups[0].GroupName != "uniquely-secret-group" {
		t.Fatalf("groups: %v %v", groups, err)
	}
	friends, invites, err := LoadPendingRequests()
	if err != nil || len(friends) != 1 || len(invites) != 1 || friends[0].Requester != "carol-secret-name" || friends[0].Target != "alice-secret-name" || invites[0].Inviter != "alice-secret-name" {
		t.Fatalf("pending: %v %v %v", friends, invites, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"alice-secret-name", "bob-secret-name", "carol-secret-name", "uniquely-secret-message", "uniquely-secret-group", "secret-date", "$argon2id$"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("plaintext remains: %s", secret)
		}
	}
	key, err := os.ReadFile(path + ".key")
	if err != nil || len(key) != 32 {
		t.Fatal("key missing/invalid")
	}
	DB.Close()
	if err = OpenDB(path); err != nil {
		t.Fatal(err)
	}
	history, err = GetChatHistory("alice-secret-name")
	if err != nil || len(history) != 1 {
		t.Fatal("reopen lost history", err)
	}
}
func TestStorageKeyFailuresDoNotReplaceKeyOrData(t *testing.T) {
	t.Setenv("CHATROOM_STORAGE_KEY_FILE", "")
	path := filepath.Join(t.TempDir(), "chat.db")
	if err := OpenDB(path); err != nil {
		t.Fatal(err)
	}
	if err := RegisterUser("alice", "secret123"); err != nil {
		t.Fatal(err)
	}
	DB.Close()
	raw, _ := os.ReadFile(path)
	key, _ := os.ReadFile(path + ".key")
	os.Remove(path + ".key")
	if err := OpenDB(path); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatal("missing key accepted", err)
	}
	if _, err := os.Stat(path + ".key"); !os.IsNotExist(err) {
		t.Fatal("missing key was recreated")
	}
	for _, bad := range [][]byte{bytes.Repeat([]byte{42}, 32), []byte("bad")} {
		os.WriteFile(path+".key", bad, 0600)
		if err := OpenDB(path); err == nil {
			t.Fatal("invalid key accepted")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(raw, after) {
			t.Fatal("key failure changed data")
		}
		actual, _ := os.ReadFile(path + ".key")
		if !bytes.Equal(actual, bad) {
			t.Fatal("invalid key was replaced")
		}
	}
	os.WriteFile(path+".key", key, 0600)
	if err := OpenDB(path); err != nil {
		t.Fatal(err)
	}
	DB.Close()
}
func TestStorageCiphertextRandomnessAndBinding(t *testing.T) {
	t.Setenv("CHATROOM_STORAGE_KEY_FILE", "")
	if err := OpenDB(filepath.Join(t.TempDir(), "chat.db")); err != nil {
		t.Fatal(err)
	}
	defer DB.Close()
	SaveFriendRelationship("alice", "bob")
	first, err := SaveMessageWithID("private", "bob", "alice", "", "same secret", "now")
	if err != nil {
		t.Fatal(err)
	}
	second, err := SaveMessageWithID("private", "bob", "alice", "", "same secret", "now")
	if err != nil {
		t.Fatal(err)
	}
	var a, b string
	DB.QueryRow("SELECT message FROM messages WHERE id=?", first).Scan(&a)
	DB.QueryRow("SELECT message FROM messages WHERE id=?", second).Scan(&b)
	if a == b {
		t.Fatal("encryption is not randomized")
	}
	for _, bad := range []string{b, "plaintext", "enc1:broken", a[:len(a)-2] + "AA"} {
		DB.Exec("UPDATE messages SET message=? WHERE id=?", bad, first)
		if _, err = GetChatHistory("alice"); err == nil {
			t.Fatal("modified/swapped/plaintext field accepted")
		}
	}
}
func TestStorageMigrationRollsBackAndResumesCleanup(t *testing.T) {
	t.Setenv("CHATROOM_STORAGE_KEY_FILE", "")
	path := filepath.Join(t.TempDir(), "chat.db")
	legacyStorageFixture(t, path)
	raw, _ := sql.Open("sqlite", path)
	raw.Exec("CREATE TRIGGER fail_migration BEFORE UPDATE ON messages BEGIN SELECT RAISE(ABORT,'migration failure'); END")
	raw.Close()
	if err := OpenDB(path); err == nil {
		t.Fatal("migration failure ignored")
	}
	raw, _ = sql.Open("sqlite", path)
	var name string
	raw.QueryRow("SELECT username FROM users WHERE id=1").Scan(&name)
	if name != "alice-secret-name" {
		t.Fatal("partial migration committed")
	}
	var count int
	raw.QueryRow("SELECT COUNT(*) FROM storage_names").Scan(&count)
	if count != 0 {
		t.Fatal("names migration not rolled back")
	}
	raw.Exec("DROP TRIGGER fail_migration")
	raw.Close()
	if err := OpenDB(path); err != nil {
		t.Fatal(err)
	}
	DB.Exec("UPDATE storage_meta SET value='1' WHERE key='cleanup_pending'")
	DB.Close()
	if err := OpenDB(path); err != nil {
		t.Fatal(err)
	}
	defer DB.Close()
	var pending string
	DB.QueryRow("SELECT value FROM storage_meta WHERE key='cleanup_pending'").Scan(&pending)
	if pending != "0" {
		t.Fatal("cleanup was not retried")
	}
}
