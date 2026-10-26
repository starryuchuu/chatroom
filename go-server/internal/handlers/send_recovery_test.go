package handlers

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/types"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReceiptDuplicatePrivateAndGroupDeliverOnce(t *testing.T) {
	for _, kind := range []string{"private", "group"} {
		t.Run(kind, func(t *testing.T) {
			manager := setupHandlers(t)
			if err := database.SaveFriendRelationship("alice", "bob"); err != nil {
				t.Fatal(err)
			}
			target := "bob"
			if kind == "group" {
				group, err := database.CreateGroup("Synthetic team", "alice", []string{"alice", "bob"})
				if err != nil {
					t.Fatal(err)
				}
				target = group.GID
			}
			key := make([]byte, 16)
			body, err := crypto.EncryptMessage("Synthetic receipt 界", key)
			if err != nil {
				t.Fatal(err)
			}
			sender, recipient := &recordConn{}, &recordConn{}
			manager.clients["bob"] = &types.ClientInfo{Conn: recipient, SessionKey: key}
			request := map[string]interface{}{"type": kind + "_chat", "request_id": "first", "idempotency_key": strings.Repeat("a", 32), "content": body}
			if kind == "group" {
				request["gid"] = target
			} else {
				request["to"] = target
			}
			for _, id := range []string{"first", "retry"} {
				request["request_id"] = id
				if kind == "group" {
					handleGroupChat(sender, "alice", key, request, manager)
				} else {
					handlePrivateChat(sender, "alice", key, request, manager)
				}
			}
			for _, reply := range recipient.messages(t) {
				stamp, ok := reply["timestamp"].(string)
				if _, err := time.Parse(time.RFC3339, stamp); !ok || err != nil || !strings.HasSuffix(stamp, "Z") {
					t.Fatal("new message is not UTC RFC3339", reply)
				}
			}
			var ids []interface{}
			for _, reply := range sender.messages(t) {
				if reply["type"] == kind+"_chat_result" {
					if reply["success"] != true {
						t.Fatal("send failed", reply)
					}
					ids = append(ids, reply["message_id"])
				}
			}
			if len(ids) != 2 || ids[0] != ids[1] || len(recipient.messages(t)) != 1 {
				t.Fatal("duplicate save or delivery", ids)
			}
		})
	}
}

func TestReceiptConcurrentPersistenceAndConflictingContent(t *testing.T) {
	setupHandlers(t)
	key := strings.Repeat("b", 32)
	var wait sync.WaitGroup
	results := make(chan database.ChatSave, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			saved, err := database.SaveChatWithReceipt("private", "alice", "bob", "", "Synthetic concurrent body", "now", false, key)
			if err != nil {
				failures <- err
			} else {
				results <- saved
			}
		}()
	}
	wait.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	var id int64
	for saved := range results {
		if id != 0 && saved.ID != id {
			t.Fatal("duplicate message committed")
		}
		id = saved.ID
	}
	if _, err := database.SaveChatWithReceipt("private", "alice", "bob", "", "Different body", "later", false, key); err == nil {
		t.Fatal("receipt key accepted different content")
	}
	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count); err != nil || count != 1 {
		t.Fatal("unexpected message count", count, err)
	}
}

func TestReceiptInsertFailureRollsBackMessage(t *testing.T) {
	setupHandlers(t)
	if _, err := database.DB.Exec(`CREATE TRIGGER fail_receipt BEFORE INSERT ON send_receipts BEGIN SELECT RAISE(ABORT,'synthetic failure'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := database.SaveChatWithReceipt("private", "alice", "bob", "", "Synthetic rollback", "now", false, strings.Repeat("c", 32))
	if err == nil {
		t.Fatal("receipt insert unexpectedly succeeded")
	}
	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count); err != nil || count != 0 {
		t.Fatal("message survived failed receipt", count, err)
	}
}

func TestReceiptStatusIsBoundToAccountAndConversation(t *testing.T) {
	setupHandlers(t)
	key := strings.Repeat("d", 32)
	saved, err := database.SaveChatWithReceipt("private", "alice", "bob", "", "Synthetic status", "saved time", false, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ who, target, status string }{{"alice", "bob", "saved"}, {"bob", "bob", "not_found"}, {"alice", "carol", "not_found"}} {
		conn := &recordConn{}
		handleMessageStatus(conn, item.who, map[string]interface{}{"request_id": "query", "idempotency_key": key, "chat_type": "private", "target": item.target})
		reply := conn.result(t, "message_status_result")
		if reply["status"] != item.status || reply["request_id"] != "query" {
			t.Fatal("receipt scope mismatch", reply)
		}
		if item.status == "saved" && (reply["message_id"] != float64(saved.ID) || reply["timestamp"] != "saved time") {
			t.Fatal("receipt lost persisted identity")
		}
	}
}
