package handlers

import (
	"chatroom/internal/database"
	"fmt"
	"sync"
	"testing"
	"time"
)

func capacityMembers(count int) []string {
	members := []string{"alice"}
	for i := 1; i < count; i++ {
		members = append(members, fmt.Sprintf("fixture-member-%03d", i))
	}
	return members
}

func TestGroupCreationBoundsRawInputAndOwnerInclusiveMembers(t *testing.T) {
	manager := setupHandlers(t)
	for _, member := range capacityMembers(maxGroupMembers + 1)[1:] {
		if err := database.SaveFriendRelationship("alice", member); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name    string
		members []string
		success bool
		count   int
	}{
		{"255_plus_owner", capacityMembers(maxGroupMembers)[1:], true, maxGroupMembers},
		{"owner_in_input", capacityMembers(maxGroupMembers), true, maxGroupMembers},
		{"256_plus_owner", capacityMembers(maxGroupMembers + 1)[1:], false, 0},
		{"oversized_duplicates", func() []string {
			v := make([]string, maxGroupMembers+1)
			for i := range v {
				v[i] = "alice"
			}
			return v
		}(), false, 0},
		{"bounded_duplicates", []string{"alice", "alice", "fixture-member-001", "fixture-member-001"}, true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &recordConn{}
			manager.AddClient("alice", conn, nil, nil)
			defer manager.RemoveClient("alice", conn)
			var before, after int
			if err := database.DB.QueryRow("SELECT COUNT(*) FROM groups").Scan(&before); err != nil {
				t.Fatal(err)
			}
			input := make([]interface{}, len(tc.members))
			for i, name := range tc.members {
				input[i] = name
			}
			handleGroupCreate(conn, "alice", map[string]interface{}{"group_name": "Capacity fixture", "members": input}, manager)
			result := conn.result(t, "group_create_result")
			if result["success"] != tc.success {
				t.Fatal("unexpected capacity decision")
			}
			if err := database.DB.QueryRow("SELECT COUNT(*) FROM groups").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if !tc.success {
				if before != after || result["error"] != groupCapacityError {
					t.Fatal("rejected creation changed storage or missed capacity error")
				}
				return
			}
			stored, err := database.GetGroup(result["gid"].(string))
			if err != nil || len(stored.Members) != tc.count {
				t.Fatal("owner-inclusive deduplication mismatch")
			}
		})
	}
}

func TestFullGroupRejectsInvitesWithoutSavingRequests(t *testing.T) {
	manager := setupHandlers(t)
	group, err := database.CreateGroup("Full fixture", "alice", capacityMembers(maxGroupMembers))
	if err != nil {
		t.Fatal(err)
	}
	conn := &recordConn{}
	handleGroupInvite(conn, "alice", map[string]interface{}{"gid": group.GID, "to": "bob"}, manager)
	result := conn.result(t, "group_invite_result")
	if result["success"] != false || result["error"] != groupCapacityError {
		t.Fatal("full group invitation accepted")
	}
	var requests int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM pending_group_invites").Scan(&requests); err != nil || requests != 0 {
		t.Fatal("rejected invitation was persisted")
	}
}

func TestConcurrentFinalJoinsReserveOnlyOneRemainingPlace(t *testing.T) {
	manager := setupHandlers(t)
	group, err := database.CreateGroup("One place fixture", "alice", capacityMembers(maxGroupMembers-1))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	pendingGroupJoins[group.GID] = make(map[string]groupInvitation)
	for _, name := range []string{"bob", "carol"} {
		if err := database.SavePendingInvite(group.GID, name, "alice", now); err != nil {
			t.Fatal(err)
		}
		pendingGroupJoins[group.GID][name] = groupInvitation{Inviter: "alice", CreatedAt: now}
	}
	connections := []*recordConn{{}, {}}
	var joined sync.WaitGroup
	for i, name := range []string{"bob", "carol"} {
		joined.Add(1)
		go func(i int, name string) {
			defer joined.Done()
			handleGroupJoin(connections[i], name, map[string]interface{}{"gid": group.GID}, manager)
		}(i, name)
	}
	joined.Wait()
	successes := 0
	for _, conn := range connections {
		result := conn.result(t, "group_join_result")
		if result["success"] == true {
			successes++
		} else if result["error"] != groupCapacityError {
			t.Fatal("unexpected rejected join reason")
		}
	}
	stored, err := database.GetGroup(group.GID)
	if err != nil || successes != 1 || len(stored.Members) != maxGroupMembers {
		t.Fatal("concurrent joins exceeded the capacity")
	}
	var requests int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM pending_group_invites WHERE gid=?", group.GID).Scan(&requests); err != nil || requests != 1 {
		t.Fatal("rejected join consumed its persisted invitation")
	}
	if len(pendingGroupJoins[group.GID]) != 1 {
		t.Fatal("rejected join consumed its memory invitation")
	}
}

func TestLegacyOversizedGroupsCanRecoverThroughLeaveOrKick(t *testing.T) {
	for _, operation := range []string{"leave", "kick"} {
		t.Run(operation, func(t *testing.T) {
			manager := setupHandlers(t)
			members := append(capacityMembers(maxGroupMembers), "bob")
			group, err := database.CreateGroup("Legacy oversized fixture", "alice", members)
			if err != nil {
				t.Fatal(err)
			}
			conn := &recordConn{}
			if operation == "leave" {
				handleGroupLeave(conn, "bob", map[string]interface{}{"gid": group.GID}, manager)
			} else {
				handleGroupKick(conn, "alice", map[string]interface{}{"gid": group.GID, "kick": "bob"}, manager)
			}
			if conn.result(t, "group_"+operation+"_result")["success"] != true {
				t.Fatal("legacy group could not recover")
			}
			stored, err := database.GetGroup(group.GID)
			if err != nil || len(stored.Members) != maxGroupMembers {
				t.Fatal("legacy recovery changed unexpected members")
			}
		})
	}
}
