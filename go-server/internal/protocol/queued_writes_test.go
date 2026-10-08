package protocol

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestQueuedWritesKeepSnapshotsAndOrderWithoutWaitingForReader(t *testing.T) {
	peer, raw := net.Pipe()
	defer peer.Close()
	conn := WrapConn(raw)
	defer conn.Close()
	EnableQueuedWrites(conn)
	payload := map[string]interface{}{"type": "group_update", "name": "Before"}
	started := time.Now()
	if err := SendMsg(conn, payload); err != nil {
		t.Fatal(err)
	}
	payload["name"] = "After"
	if err := SendMsg(conn, payload); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("enqueue waited for a slow reader")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	for _, expected := range []string{"Before", "After"} {
		msg, err := RecvMsg(peer)
		if err != nil || msg["name"] != expected {
			t.Fatalf("%v %v", msg, err)
		}
	}
}

func TestQueuedWriterTimeoutClosesSlowConnection(t *testing.T) {
	peer, raw := net.Pipe()
	defer peer.Close()
	conn := WrapConn(raw)
	defer conn.Close()
	EnableQueuedWrites(conn)
	if err := SendMsg(conn, map[string]string{"content": "never read"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.done:
	case <-time.After(WriteTimeout + time.Second):
		t.Fatal("slow writer was not closed")
	}
	if err := SendMsg(conn, map[string]string{"content": "closed"}); err != net.ErrClosed {
		t.Fatalf("%v", err)
	}
}

func TestQueuedWriterBackpressureClosesConnectionWithoutBlockingHandler(t *testing.T) {
	peer, raw := net.Pipe()
	defer peer.Close()
	conn := WrapConn(raw)
	defer conn.Close()
	EnableQueuedWrites(conn)
	var err error
	started := time.Now()
	for i := 0; i < 258; i++ {
		err = SendMsg(conn, map[string]int{"id": i})
		if err != nil {
			break
		}
	}
	if err == nil || !strings.Contains(err.Error(), "full") || time.Since(started) > time.Second {
		t.Fatalf("queue failed to bound a slow consumer: %v", err)
	}
	select {
	case <-conn.done:
	default:
		t.Fatal("full queue left connection open")
	}
}
