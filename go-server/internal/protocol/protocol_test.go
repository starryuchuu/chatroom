package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type testConn struct {
	input    *bytes.Reader
	output   bytes.Buffer
	chunk    int
	deadline time.Time
	closed   bool
}

func (c *testConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *testConn) Write(p []byte) (int, error) {
	if c.chunk > 0 && len(p) > c.chunk {
		p = p[:c.chunk]
	}
	return c.output.Write(p)
}
func (c *testConn) Close() error                       { c.closed = true; return nil }
func (c *testConn) LocalAddr() net.Addr                { return nil }
func (c *testConn) RemoteAddr() net.Addr               { return nil }
func (c *testConn) SetDeadline(time.Time) error        { return nil }
func (c *testConn) SetReadDeadline(time.Time) error    { return nil }
func (c *testConn) SetWriteDeadline(t time.Time) error { c.deadline = t; return nil }

func TestRejectOversizeBeforeAllocation(t *testing.T) {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 2*1024*1024)
	conn := &testConn{input: bytes.NewReader(header)}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := RecvMsg(conn)
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected length rejection, got %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 256*1024 {
		t.Fatalf("allocated %d bytes before rejecting header", allocated)
	}
}

func TestSendHandlesShortWrites(t *testing.T) {
	conn := &testConn{input: bytes.NewReader(nil), chunk: 1}
	if err := SendMsg(conn, map[string]string{"type": "test"}); err != nil {
		t.Fatal(err)
	}
	reader := &testConn{input: bytes.NewReader(conn.output.Bytes())}
	msg, err := RecvMsg(reader)
	if err != nil || msg["type"] != "test" {
		t.Fatalf("frame truncated: %v, %v", msg, err)
	}
}

func TestRecvRejectsMalformedJSON(t *testing.T) {
	for _, body := range []string{"not-json", "null", "[]", ""} {
		t.Run(body, func(t *testing.T) {
			var frame bytes.Buffer
			binary.Write(&frame, binary.BigEndian, uint32(len(body)))
			frame.WriteString(body)
			_, err := RecvMsg(&testConn{input: bytes.NewReader(frame.Bytes())})
			if err == nil {
				t.Fatal("malformed object accepted")
			}
		})
	}
}

func TestRecvTruncatedBody(t *testing.T) {
	_, err := RecvMsg(&testConn{input: bytes.NewReader([]byte{0, 0, 0, 8, '{'})})
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("got %v", err)
	}
}

func TestSendRenewsExpiredDeadline(t *testing.T) {
	peer, remote := net.Pipe()
	defer peer.Close()
	defer remote.Close()
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	remote.SetWriteDeadline(time.Now().Add(-time.Second))
	done := make(chan error, 1)
	go func() { done <- SendMsg(WrapConn(remote), map[string]string{"type": "after-timeout"}) }()
	msg, err := RecvMsg(peer)
	if err != nil || msg["type"] != "after-timeout" {
		t.Fatalf("expired deadline wasn't renewed: %v %v", msg, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentFramesNeverInterleave(t *testing.T) {
	raw := &testConn{input: bytes.NewReader(nil), chunk: 1}
	conn := WrapConn(raw)
	const count = 64
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := SendMsg(conn, map[string]interface{}{"id": i, "text": strings.Repeat("x", 128)}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	reader := &testConn{input: bytes.NewReader(raw.output.Bytes())}
	seen := make(map[float64]bool)
	for i := 0; i < count; i++ {
		msg, err := RecvMsg(reader)
		if err != nil {
			t.Fatal(err)
		}
		id, ok := msg["id"].(float64)
		if !ok || seen[id] {
			t.Fatalf("duplicate/malformed frame: %v", msg)
		}
		seen[id] = true
	}
	if reader.input.Len() != 0 {
		t.Fatal("unexpected bytes after frames")
	}
}

type zeroWriteConn struct{ testConn }

func (c *zeroWriteConn) Write([]byte) (int, error) { return 0, nil }
func TestZeroWriteClosesConnection(t *testing.T) {
	conn := &zeroWriteConn{}
	if err := SendMsg(conn, map[string]string{"type": "x"}); err != io.ErrShortWrite {
		t.Fatalf("got %v", err)
	}
	if !conn.closed {
		t.Fatal("failed partial frame left connection open")
	}
}

func TestMaximumUint32HeaderRejected(t *testing.T) {
	_, err := RecvMsg(&testConn{input: bytes.NewReader([]byte{255, 255, 255, 255})})
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("got %v", err)
	}
}
