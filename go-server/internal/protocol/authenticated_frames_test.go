package protocol

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func testAuth(server bool) *frameAuth {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	a := &frameAuth{sendKey: directionalKey(key, "client"), recvKey: directionalKey(key, "server")}
	if server {
		a.sendKey, a.recvKey = a.recvKey, a.sendKey
	}
	return a
}
func TestAuthenticatedFramesRejectTamperingReplayReflection(t *testing.T) {
	sender, receiver := testAuth(false), testAuth(true)
	frame, err := sender.encode([]byte(`{"type":"private_chat","to":"bob"}`))
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(frame, []byte("bob"), []byte("eve"), 1)
	if _, err = receiver.decode(tampered); err == nil {
		t.Fatal("tampered routing field accepted")
	}
	if receiver.recvSeq != 0 {
		t.Fatal("invalid MAC consumed receive counter")
	}
	if _, err = receiver.decode(frame); err != nil {
		t.Fatal(err)
	}
	if _, err = receiver.decode(frame); err == nil {
		t.Fatal("replayed frame accepted")
	}
	if _, err = testAuth(false).decode(frame); err == nil {
		t.Fatal("reflected frame accepted")
	}
	if _, err = testAuth(true).decode([]byte(`{"type":"group_disband","gid":"group"}`)); err == nil {
		t.Fatal("plaintext control accepted")
	}
}
func TestAuthenticatedFrameCrossLanguageVectorAndLimit(t *testing.T) {
	sender := testAuth(false)
	frame, err := sender.encode([]byte(`{"type":"group_leave","gid":"g"}`))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(frame) != "00000000000000007b2274797065223a2267726f75705f6c65617665222c22676964223a2267227d726a29b0e5069e813061c813a2775974391a9db833691553be4e467fe7bc0ade" {
		t.Fatal("Python/Go vector mismatch")
	}
	frame, err = sender.encode(make([]byte, MaxMessageLen))
	if err != nil || len(frame) != MaxWireLen {
		t.Fatal(fmt.Sprint(len(frame), err))
	}
	if _, err = sender.encode(make([]byte, MaxMessageLen+1)); err == nil {
		t.Fatal("wire limit omitted authentication overhead")
	}
}
