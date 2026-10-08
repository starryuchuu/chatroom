package database

import (
	"path/filepath"
	"testing"
)

func TestHistorySnapshotUsesCommittedIDsGlobalOrderAndFriendFilter(t *testing.T) {
	InitDB(filepath.Join(t.TempDir(), "chat.db"))
	DB.SetMaxOpenConns(1)
	t.Cleanup(func() { DB.Close() })
	if err := SaveFriendRelationship("alice", "bob"); err != nil {
		t.Fatal(err)
	}
	group, err := CreateGroup("Team", "alice", []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, kind := range []string{"private", "group", "private"} {
		id, err := SaveMessageWithID(kind, "bob", "alice", group.GID, kind, "now")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	boundary, err := SaveMessageWithID("private", "stranger", "alice", "", "must be filtered", "now")
	if err != nil {
		t.Fatal(err)
	}
	history, actualBoundary, err := GetChatHistorySnapshot("alice")
	if err != nil || actualBoundary != boundary || len(history) != len(ids) {
		t.Fatalf("%v %d %v", history, actualBoundary, err)
	}
	for i, message := range history {
		if message.ID != ids[i] {
			t.Fatalf("history ID/order: %+v", history)
		}
	}
	// NULL columns from existing Python databases must remain readable.
	if _, err := DB.Exec("INSERT INTO messages(chat_type,from_user,to_user,message,timestamp) VALUES('private','bob','alice','python','now')"); err != nil {
		t.Fatal(err)
	}
	history, _, err = GetChatHistorySnapshot("alice")
	if err != nil || len(history) != 4 {
		t.Fatalf("NULL compatibility: %v %v", history, err)
	}
}

func TestSaveMessageWithIDReportsFailure(t *testing.T) {
	InitDB(filepath.Join(t.TempDir(), "chat.db"))
	t.Cleanup(func() { DB.Close() })
	DB.Exec("DROP TABLE messages")
	if id, err := SaveMessageWithID("private", "alice", "bob", "", "failed", "now"); id != 0 || err == nil {
		t.Fatalf("%d %v", id, err)
	}
}
