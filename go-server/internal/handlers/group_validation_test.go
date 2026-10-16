package handlers

import (
	"chatroom/internal/database"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The subprocess keeps an old implementation's blocked goroutines and locks
// from leaking into unrelated tests after the completion assertion fails.
func TestGroupCreateAndLoginSnapshotDoNotDeadlock(t *testing.T) {
	const helperEnv = "CHATROOM_TEST_CREATE_LOGIN_HELPER"
	if os.Getenv(helperEnv) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGroupCreateAndLoginSnapshotDoNotDeadlock$", "-test.count=1")
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("group creation/login subprocess failed: %v\n%s", err, output)
		}
		return
	}

	manager := setupHandlers(t)
	owner := &recordConn{}
	manager.AddClient("alice", owner, nil, nil)
	// Hold the only database connection so creation must stop after its first
	// catalog read lock, before acquiring the new group's operation lock.
	tx, err := database.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	created := make(chan struct{})
	go func() {
		handleGroupCreate(owner, "alice", map[string]interface{}{"group_name": "Team", "members": []interface{}{}}, manager)
		close(created)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for groupCatalogMu.TryLock() {
		groupCatalogMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("creation did not acquire the catalog read lock")
		}
		runtime.Gosched()
	}
	synced := make(chan error, 1)
	go func() { synced <- SendUserGroups(owner, "alice") }()
	for groupCatalogMu.TryRLock() {
		groupCatalogMu.RUnlock()
		if time.Now().After(deadline) {
			t.Fatal("login did not queue for the catalog write lock")
		}
		runtime.Gosched()
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-created:
	case <-time.After(3 * time.Second):
		t.Fatal("group creation deadlocked behind the queued login snapshot")
	}
	select {
	case err = <-synced:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("login snapshot did not finish after group creation")
	}
	messages := owner.messages(t)
	if len(messages) != 2 || messages[0]["type"] != "group_create_result" || messages[1]["type"] != "user_groups_list" {
		t.Fatalf("creation notification must precede the login snapshot: %v", messages)
	}
	groups := messages[1]["groups"].([]interface{})
	if len(groups) != 1 || groups[0].(map[string]interface{})["gid"] != messages[0]["gid"] {
		t.Fatal("login snapshot did not contain the committed group")
	}
}

func TestGroupNamesRejectInvalidValuesBeforeMutation(t *testing.T) {
	manager := setupHandlers(t)
	observer := &recordConn{}
	manager.AddClient("bob", observer, nil, nil)
	group, err := database.CreateGroup("Before", "alice", []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ label, name string }{
		{"empty", ""},
		{"ascii_whitespace", " \t\n"},
		{"unicode_whitespace", "\u3000\u00a0"},
		{"ascii_129", strings.Repeat("a", 129)},
		{"unicode_129", strings.Repeat("界", 129)},
	} {
		t.Run("create/"+tc.label, func(t *testing.T) {
			conn := &recordConn{}
			manager.AddClient("alice", conn, nil, nil)
			defer manager.RemoveClient("alice", conn)
			handleGroupCreate(conn, "alice", map[string]interface{}{"group_name": tc.name, "members": []interface{}{}}, manager)
			if conn.result(t, "group_create_result")["success"] != false {
				t.Fatal("invalid name accepted")
			}
			var count int
			if err := database.DB.QueryRow("SELECT COUNT(*) FROM groups").Scan(&count); err != nil || count != 1 {
				t.Fatalf("invalid create changed storage: groups=%d err=%v", count, err)
			}
		})
		t.Run("rename/"+tc.label, func(t *testing.T) {
			conn := &recordConn{}
			handleGroupRename(conn, "alice", map[string]interface{}{"gid": group.GID, "new_name": tc.name}, manager)
			if conn.result(t, "group_rename_result")["success"] != false {
				t.Fatal("invalid name accepted")
			}
			stored, err := database.GetGroup(group.GID)
			if err != nil || stored.GroupName != "Before" {
				t.Fatalf("invalid rename changed storage: %v %v", stored, err)
			}
		})
	}
	if len(observer.messages(t)) != 0 {
		t.Fatal("invalid names generated a group update for another member")
	}
}

func TestGroupNamesAllow128UnicodeCharacters(t *testing.T) {
	manager := setupHandlers(t)
	owner := &recordConn{}
	manager.AddClient("alice", owner, nil, nil)
	name := strings.Repeat("🚀", 128)
	handleGroupCreate(owner, "alice", map[string]interface{}{"group_name": name, "members": []interface{}{}}, manager)
	created := owner.result(t, "group_create_result")
	if created["success"] != true || created["group_name"] != name {
		t.Fatalf("128 Unicode characters rejected: %v", created)
	}
	newName := strings.Repeat("界", 128)
	renamed := &recordConn{}
	handleGroupRename(renamed, "alice", map[string]interface{}{"gid": created["gid"], "new_name": newName}, manager)
	if renamed.result(t, "group_rename_result")["success"] != true {
		t.Fatal("128 Unicode character rename rejected")
	}
	stored, err := database.GetGroup(created["gid"].(string))
	if err != nil || stored.GroupName != newName {
		t.Fatalf("name not preserved: %v %v", stored, err)
	}
}

func TestRenameLegacyOversizedGroupNameHasDeliverableNotifications(t *testing.T) {
	manager := setupHandlers(t)
	group, err := database.CreateGroup(strings.Repeat("界", 400000), "alice", []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	alice, bob := &recordConn{}, &recordConn{}
	manager.AddClient("bob", bob, nil, nil)
	handleGroupRename(alice, "alice", map[string]interface{}{"gid": group.GID, "new_name": "Repaired"}, manager)
	for _, result := range []map[string]interface{}{alice.result(t, "group_rename_result"), bob.result(t, "group_rename_notification")} {
		if result["old_name"] != strings.Repeat("界", 128) || result["new_name"] != "Repaired" {
			t.Fatal("legacy name was not truncated safely in the notification")
		}
	}
	if alice.result(t, "group_rename_result")["success"] != true {
		t.Fatal("legacy group rename failed")
	}
	stored, err := database.GetGroup(group.GID)
	if err != nil || stored.GroupName != "Repaired" {
		t.Fatalf("legacy group was not repaired: %v %v", stored, err)
	}
}
