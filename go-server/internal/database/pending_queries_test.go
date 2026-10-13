package database

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPendingRequestsSurviveDatabaseReopenAndExpire(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chat.db")
	InitDB(path)
	now := time.Now()
	if err := SavePendingFriend("alice", "bob", now); err != nil {
		t.Fatal(err)
	}
	if err := SavePendingInvite("g", "bob", "alice", now); err != nil {
		t.Fatal(err)
	}
	SavePendingFriend("old", "bob", now.Add(-25*time.Hour))
	DB.Close()
	InitDB(path)
	t.Cleanup(func() { DB.Close() })
	friends, invites, err := LoadPendingRequests()
	if err != nil || len(friends) != 1 || len(invites) != 1 {
		t.Fatalf("reopen: %v %v %v", friends, invites, err)
	}
	if friends[0].Requester != "alice" || invites[0].Inviter != "alice" {
		t.Fatal("request identity lost")
	}
	if err := SaveFriendRelationship("bob", "alice"); err != nil {
		t.Fatal(err)
	}
	friends, _, err = LoadPendingRequests()
	if err != nil || len(friends) != 0 {
		t.Fatal("accept did not consume durable request")
	}
	if err := DeletePendingInvite("g", "bob"); err != nil {
		t.Fatal(err)
	}
	_, invites, err = LoadPendingRequests()
	if err != nil || len(invites) != 0 {
		t.Fatal("decline did not consume durable invitation")
	}
}

func TestHistoryPagesAreBoundedCompleteAndFiltered(t *testing.T) {
	InitDB(filepath.Join(t.TempDir(), "chat.db"))
	DB.SetMaxOpenConns(1)
	t.Cleanup(func() { DB.Close() })
	SaveFriendRelationship("alice", "bob")
	tx, err := DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 205; i++ {
		if _, err = tx.Exec("INSERT INTO messages(chat_type,from_user,to_user,message,timestamp) VALUES('private','bob','alice','body','now')"); err != nil {
			t.Fatal(err)
		}
	}
	tx.Commit()
	SaveMessage("private", "stranger", "alice", "", "hidden", "now")
	boundary, err := HistoryBoundary()
	if err != nil {
		t.Fatal(err)
	}
	before := int64(0)
	seen := map[int64]bool{}
	for _, size := range []int{100, 100, 5} {
		page, more, err := GetHistoryPage("alice", boundary, before, "private", "bob")
		if err != nil || len(page) != size || more != (size == 100) {
			t.Fatalf("page: %d %t %v", len(page), more, err)
		}
		for _, m := range page {
			if seen[m.ID] {
				t.Fatal("duplicate across pages")
			}
			seen[m.ID] = true
		}
		before = page[0].ID
	}
	if len(seen) != 205 || !seen[1] || !seen[205] {
		t.Fatal("history missing records")
	}
	page, _, err := GetHistoryPage("alice", boundary, 0, "private", "stranger")
	if err != nil || len(page) != 0 {
		t.Fatal("non-friend history exposed")
	}
}
