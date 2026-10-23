package handlers

import (
	"bytes"
	"chatroom/internal/database"
	"encoding/binary"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

type privateLogInputConn struct {
	recordConn
	input *bytes.Reader
}

func (c *privateLogInputConn) Read(p []byte) (int, error) { return c.input.Read(p) }

func TestMalformedAndUnknownMessagesDoNotLogInput(t *testing.T) {
	for _, kind := range []interface{}{17, "synthetic-private-type\nforged-log"} {
		var output bytes.Buffer
		previous := log.Writer()
		log.SetOutput(&output)
		body, _ := json.Marshal(map[string]interface{}{"type": kind, "password": "synthetic-private-password", "content": "synthetic-private-body", "members": []string{"synthetic-private-member"}})
		wire := make([]byte, 4+len(body))
		binary.BigEndian.PutUint32(wire, uint32(len(body)))
		copy(wire[4:], body)
		conn := &privateLogInputConn{input: bytes.NewReader(wire)}
		HandleClientMessages(conn, "synthetic-private-account", nil, nil)
		log.SetOutput(previous)
		for _, secret := range []string{"synthetic-private-password", "synthetic-private-body", "synthetic-private-member", "synthetic-private-account", "synthetic-private-type", "forged-log"} {
			if strings.Contains(output.String(), secret) {
				t.Fatal("untrusted message data reached default logs")
			}
		}
		if !strings.Contains(output.String(), "event=") {
			t.Fatal("missing safe diagnostic event")
		}
	}
}

func TestGroupTopicsAndMembersDoNotReachDefaultLogs(t *testing.T) {
	manager := setupHandlers(t)
	privateMember := "synthetic-private-member"
	if err := database.SaveFriendRelationship("alice", privateMember); err != nil {
		t.Fatal(err)
	}
	conn := &recordConn{}
	manager.AddClient("alice", conn, nil, nil)
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	handleGroupCreate(conn, "alice", map[string]interface{}{"group_name": "synthetic-private-topic", "members": []interface{}{privateMember}}, manager)
	created := conn.result(t, "group_create_result")
	if created["success"] != true {
		t.Fatal("fixture creation failed")
	}
	handleGroupRename(&recordConn{}, "alice", map[string]interface{}{"gid": created["gid"], "new_name": "synthetic-private-renamed-topic"}, manager)
	for _, secret := range []string{privateMember, "synthetic-private-topic", "synthetic-private-renamed-topic"} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("private group metadata reached default logs")
		}
	}
	if !strings.Contains(output.String(), "members=2") {
		t.Fatal("safe group size diagnostic missing")
	}
}
