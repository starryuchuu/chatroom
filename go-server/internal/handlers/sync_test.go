package handlers

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/protocol"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestSyncRequestWirePaginationAndReplayMarkers(t *testing.T) {
	setupHandlers(t)
	if err := database.SaveFriendRelationship("alice", "bob"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 102; i++ {
		if err := database.SaveMessage("private", "alice", "bob", "", fmt.Sprintf("body-%d", i), "now"); err != nil {
			t.Fatal(err)
		}
	}
	key := make([]byte, 16)
	first := &recordConn{}
	handleSyncRequest(first, "bob", key, map[string]interface{}{"request_id": "page-1", "after_id": float64(0)})
	begin := first.result(t, "sync_begin")
	end := first.result(t, "sync_end")
	if begin["request_id"] != "page-1" || begin["after_id"] != float64(0) || begin["boundary"] != float64(102) ||
		end["request_id"] != "page-1" || end["after_id"] != float64(0) || end["boundary"] != float64(102) || end["next_after_id"] != float64(100) || end["has_more"] != true {
		t.Fatalf("wrong first page boundaries: %v %v", begin, end)
	}
	var expectedID float64 = 1
	checkMessages := func(conn *recordConn) {
		t.Helper()
		for _, message := range conn.messages(t) {
			if message["type"] != "private_chat" {
				continue
			}
			if message["message_id"] != expectedID || message["history"] != true || message["sync"] != true || message["to"] != "bob" {
				t.Fatalf("unmarked or misordered replay: %v", message)
			}
			body, err := crypto.DecryptMessage(message["content"].(string), key)
			if err != nil || body != fmt.Sprintf("body-%d", int(expectedID)-1) {
				t.Fatalf("replay plaintext: %s %v", body, err)
			}
			expectedID++
		}
	}
	checkMessages(first)
	if err := database.SaveMessage("private", "alice", "bob", "", "live after boundary", "later"); err != nil {
		t.Fatal(err)
	}
	second := &recordConn{}
	handleSyncRequest(second, "bob", key, map[string]interface{}{"request_id": "page-2", "after_id": end["next_after_id"], "boundary": end["boundary"]})
	checkMessages(second)
	end = second.result(t, "sync_end")
	if expectedID != 103 || end["next_after_id"] != float64(102) || end["has_more"] != false || end["boundary"] != float64(102) {
		t.Fatalf("second page escaped the snapshot: %v next message %.0f", end, expectedID)
	}
	// Existing login/manual history remains compatible and explicitly marked.
	history := &recordConn{}
	if err := SendHistory(history, "bob", key, "private", "alice", 0); err != nil {
		t.Fatal(err)
	}
	message := history.result(t, "private_chat")
	if message["history"] != true || message["sync"] != nil {
		t.Fatal("manual history was not distinguished from live/catch-up messages")
	}
}

func TestSyncRejectsMalformedOrExpiredCursorsWithoutAdvancing(t *testing.T) {
	setupHandlers(t)
	invalid := []map[string]interface{}{
		{},
		{"request_id": "", "after_id": float64(0)},
		{"request_id": strings.Repeat("名", 129), "after_id": float64(0)},
		{"request_id": true, "after_id": float64(0)},
		{"request_id": "a", "after_id": nil},
		{"request_id": "a", "after_id": true},
		{"request_id": "a", "after_id": "0"},
		{"request_id": "a", "after_id": float64(-1)},
		{"request_id": "a", "after_id": 0.5},
		{"request_id": "a", "after_id": math.NaN()},
		{"request_id": "a", "after_id": math.Inf(1)},
		{"request_id": "a", "after_id": float64(maxSyncCursor) + 1},
		{"request_id": "a", "after_id": float64(1)}, // Cursor is ahead of the empty server.
		{"request_id": "a", "after_id": float64(0), "boundary": nil},
		{"request_id": "a", "after_id": float64(0), "boundary": false},
		{"request_id": "a", "after_id": float64(0), "boundary": float64(-1)},
		{"request_id": "a", "after_id": float64(0), "boundary": 0.5},
		{"request_id": "a", "after_id": float64(0), "boundary": float64(1)},
	}
	for i, request := range invalid {
		conn := &recordConn{}
		handleSyncRequest(conn, "alice", make([]byte, 16), request)
		messages := conn.messages(t)
		if len(messages) != 1 || messages[0]["type"] != "sync_error" {
			t.Fatalf("invalid request %d advanced the sync: %v", i, messages)
		}
		if request["request_id"] == "a" && messages[0]["request_id"] != "a" {
			t.Fatal("invalid numeric input lost response correlation")
		}
	}
	valid := &recordConn{}
	handleSyncRequest(valid, "alice", make([]byte, 16), map[string]interface{}{"request_id": strings.Repeat("名", 128), "after_id": float64(0), "boundary": float64(0)})
	end := valid.result(t, "sync_end")
	if end["after_id"] != float64(0) || end["boundary"] != float64(0) || end["next_after_id"] != float64(0) || end["has_more"] != false {
		t.Fatalf("empty sync cannot complete after invalid requests: %v", end)
	}
	if value, ok := syncCursor(float64(maxSyncCursor)); !ok || value != maxSyncCursor {
		t.Fatal("largest safe cursor was rounded or rejected")
	}
}

type changingSyncConn struct {
	recordConn
	beforeRows func()
}

func (conn *changingSyncConn) Write(packet []byte) (int, error) {
	var message map[string]interface{}
	if err := json.Unmarshal(packet[4:], &message); err == nil && message["type"] == "sync_begin" && conn.beforeRows != nil {
		change := conn.beforeRows
		conn.beforeRows = nil
		change()
	}
	return conn.recordConn.Write(packet)
}

func TestSyncRechecksMembershipBeforeEnqueuingEachGroupMessage(t *testing.T) {
	setupHandlers(t)
	group, err := database.CreateGroup("Shared", "alice", []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if err = database.SaveMessage("group", "alice", "", group.GID, "not after removal", "now"); err != nil {
		t.Fatal(err)
	}
	conn := &changingSyncConn{beforeRows: func() {
		unlock := LockGroup(group.GID)
		defer unlock()
		if err := database.UpdateGroupMembers(group.GID, []string{"alice"}); err != nil {
			t.Fatal(err)
		}
	}}
	handleSyncRequest(conn, "bob", make([]byte, 16), map[string]interface{}{"request_id": "member-change", "after_id": float64(0)})
	for _, message := range conn.messages(t) {
		if message["type"] == "group_chat" {
			t.Fatal("member removed after the page query received a group message")
		}
	}
	if end := conn.result(t, "sync_end"); end["next_after_id"] != float64(1) {
		t.Fatal("skipping revoked messages stalled the cursor")
	}
}

func TestSyncStorageFailureNeverCompletesAPartialPage(t *testing.T) {
	setupHandlers(t)
	if err := database.SaveFriendRelationship("alice", "bob"); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveMessage("private", "alice", "bob", "", "private body", "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.DB.Exec("UPDATE messages SET message='damaged storage'"); err != nil {
		t.Fatal(err)
	}
	conn := &recordConn{}
	handleSyncRequest(conn, "bob", make([]byte, 16), map[string]interface{}{"request_id": "retry-me", "after_id": float64(0)})
	messages := conn.messages(t)
	if len(messages) != 1 || messages[0]["type"] != "sync_error" || messages[0]["request_id"] != "retry-me" {
		t.Fatal("damaged storage was acknowledged as a completed sync")
	}
}

func TestLegacyNearLimitMessagesRemainReplayableWithoutTruncation(t *testing.T) {
	for _, largeID := range []bool{false, true} {
		t.Run(fmt.Sprintf("large_id_%t", largeID), func(t *testing.T) {
			manager := setupHandlers(t)
			if err := database.SaveFriendRelationship("alice", "bob"); err != nil {
				t.Fatal(err)
			}
			key := make([]byte, 16)
			timestamp := "2000-01-01 00:00:00"
			legacyBase := chatPayload("private_chat", "alice", "bob", "", timestamp, math.MaxInt64)
			delete(legacyBase, "history") // Old releases did not mark live frames.
			base, err := json.Marshal(legacyBase)
			if err != nil {
				t.Fatal(err)
			}
			// AES-GCM uses 16 nonce bytes and 16 tag bytes before Base64.
			body := strings.Repeat("a", 3*((protocol.MaxMessageLen-len(base))/4)-32)
			content, err := crypto.EncryptMessage(body, key)
			if err != nil {
				t.Fatal(err)
			}
			legacy := chatPayload("private_chat", "alice", "bob", content, timestamp, math.MaxInt64)
			delete(legacy, "history")
			if err = protocol.ValidateMessage(legacy); err != nil {
				t.Fatalf("fixture was not accepted by the legacy size check: %v", err)
			}
			conn := &recordConn{}
			handlePrivateChat(conn, "alice", key, map[string]interface{}{"to": "bob", "content": content, "request_id": "reserve-flags"}, manager)
			if conn.result(t, "private_chat_result")["success"] != false {
				t.Fatal("future acceptance failed to reserve replay metadata")
			}
			if largeID {
				if _, err = database.DB.Exec("INSERT INTO sqlite_sequence(name,seq) VALUES('messages',?)", maxSyncCursor-1); err != nil {
					t.Fatal(err)
				}
			}
			id, err := database.SaveMessageWithID("private", "alice", "bob", "", body, timestamp)
			if err != nil {
				t.Fatal(err)
			}
			replay := &recordConn{}
			handleSyncRequest(replay, "bob", key, map[string]interface{}{"request_id": "legacy", "after_id": float64(0)})
			message := replay.result(t, "private_chat")
			plain, err := crypto.DecryptMessage(message["content"].(string), key)
			if err != nil || plain != body || message["message_id"] != float64(id) || message["sync"] != nil {
				t.Fatalf("legacy payload was changed: id=%v err=%v", message["message_id"], err)
			}
			if largeID && message["history"] != nil {
				t.Fatal("largest legacy ID did not shed the remaining optional flag")
			}
			if !largeID && message["history"] != true {
				t.Fatal("replay discarded a history marker despite room for it")
			}
			if end := replay.result(t, "sync_end"); end["next_after_id"] != float64(id) || end["has_more"] != false {
				t.Fatal("legacy replay failed to complete")
			}
			manual := &recordConn{}
			if err = SendHistory(manual, "bob", key, "private", "alice", 0); err != nil {
				t.Fatalf("manual history lost a legacy near-limit message: %v", err)
			}
			if restored, err := crypto.DecryptMessage(manual.result(t, "private_chat")["content"].(string), key); err != nil || restored != body {
				t.Fatal("manual history truncated a legacy message")
			}
		})
	}
}
