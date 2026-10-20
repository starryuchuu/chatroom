package database

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSyncPagesRecoverCompleteMixedConversationGapWithinSnapshot(t *testing.T) {
	InitDB(filepath.Join(t.TempDir(), "chat.db"))
	t.Cleanup(func() { DB.Close() })
	if err := SaveFriendRelationship("alice", "bob"); err != nil {
		t.Fatal(err)
	}
	group, err := CreateGroup("Shared", "alice", []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	hidden, err := CreateGroup("Private", "alice", []string{"alice"})
	if err != nil {
		t.Fatal(err)
	}
	var expected []int64
	for i := 0; i < 205; i++ {
		kind, to, gid := "private", "bob", ""
		if i%2 == 1 {
			kind, to, gid = "group", "", group.GID
		}
		id, err := SaveMessageWithID(kind, "alice", to, gid, fmt.Sprintf("message-%d", i), "now")
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, id)
		// Unrelated private messages and groups must not leak into catch-up.
		if i%20 == 0 {
			if err = SaveMessage("private", "carol", "bob", "", "not friends", "now"); err != nil {
				t.Fatal(err)
			}
			if err = SaveMessage("group", "alice", "", hidden.GID, "not a member", "now"); err != nil {
				t.Fatal(err)
			}
		}
	}
	boundary, err := HistoryBoundary()
	if err != nil {
		t.Fatal(err)
	}
	var received []int64
	after := int64(0)
	var late int64
	for page, size := range []int{100, 100, 5} {
		messages, more, err := GetSyncPage("bob", boundary, after)
		if err != nil || len(messages) != size || more != (page < 2) {
			t.Fatalf("page %d: %d more=%t err=%v", page, len(messages), more, err)
		}
		for _, message := range messages {
			if message.ID <= after || message.FromUser != "alice" || message.Content != fmt.Sprintf("message-%d", len(received)) {
				t.Fatalf("wrong forward page content: %+v", message)
			}
			received = append(received, message.ID)
			after = message.ID
		}
		if page == 0 {
			late, err = SaveMessageWithID("private", "alice", "bob", "", "after snapshot", "later")
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if !reflect.DeepEqual(received, expected) {
		t.Fatal("sync duplicated or skipped messages")
	}
	current, err := HistoryBoundary()
	if err != nil {
		t.Fatal(err)
	}
	messages, more, err := GetSyncPage("bob", current, boundary)
	if err != nil || more || len(messages) != 1 || messages[0].ID != late || messages[0].Content != "after snapshot" {
		t.Fatalf("next snapshot lost the live message: %v %t %v", messages, more, err)
	}
	if err = UpdateGroupMembers(group.GID, []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	messages, _, err = GetSyncPage("bob", current, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range messages {
		if message.ChatType != "private" {
			t.Fatal("removed member recovered group history")
		}
	}
}
