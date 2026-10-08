package handlers

import (
	"chatroom/internal/protocol"
	"net"
	"testing"
	"time"
)

func TestRejectedAuthNeverReturnsSuccess(t *testing.T) {
	for _, kind := range []string{"encrypted_login", "encrypted_register", "login"} {
		t.Run(kind, func(t *testing.T) {
			peer, remote := net.Pipe()
			defer peer.Close()
			defer remote.Close()
			peer.SetDeadline(time.Now().Add(3 * time.Second))
			result := make(chan error, 1)
			go func() {
				user, err := HandleAuth(remote, make([]byte, 16), nil)
				if user != "" {
					t.Errorf("unexpected identity %q", user)
				}
				result <- err
			}()
			if err := protocol.SendMsg(peer, map[string]interface{}{"type": kind}); err != nil {
				t.Fatal(err)
			}
			msg, err := protocol.RecvMsg(peer)
			if err != nil || msg["success"] != false {
				t.Fatalf("missing rejection: %v %v", msg, err)
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("rejected auth returned nil error; caller would create empty-user session")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("authentication did not finish")
			}
		})
	}
}
