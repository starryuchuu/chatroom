package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const MaxMessageLen = 1024 * 1024
const WriteTimeout = 30 * time.Second

// Conn serializes complete frames sent by concurrent handlers and broadcasts.
// Its lock belongs to the connection, so closed sessions need no global cleanup.
type Conn struct {
	net.Conn
	writeMu sync.Mutex
}

func WrapConn(conn net.Conn) *Conn {
	if wrapped, ok := conn.(*Conn); ok {
		return wrapped
	}
	return &Conn{Conn: conn}
}

// SendMsg sends one length-prefixed JSON frame. Shared server connections must
// be wrapped once with WrapConn before being published to other goroutines.
func SendMsg(conn net.Conn, msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(data) > MaxMessageLen {
		return fmt.Errorf("message too large: %d bytes (max: %d)", len(data), MaxMessageLen)
	}
	if wrapped, ok := conn.(*Conn); ok {
		wrapped.writeMu.Lock()
		defer wrapped.writeMu.Unlock()
	}
	// Refresh inside the frame lock; a deadline set at connection establishment
	// expires even when a session remains active.
	if err := conn.SetWriteDeadline(time.Now().Add(WriteTimeout)); err != nil {
		return err
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)
	for len(frame) > 0 {
		n, err := conn.Write(frame)
		if err != nil {
			conn.Close()
			return err
		}
		if n <= 0 || n > len(frame) {
			conn.Close()
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func RecvMsg(conn net.Conn) (map[string]interface{}, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	msgLen := binary.BigEndian.Uint32(header[:])
	// Validate BEFORE allocating memory, including lengths near uint32's limit.
	if msgLen > MaxMessageLen {
		return nil, fmt.Errorf("message too large: %d bytes (max: %d)", msgLen, MaxMessageLen)
	}
	if msgLen == 0 {
		return nil, fmt.Errorf("empty message")
	}
	data := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, fmt.Errorf("message must be a JSON object")
	}
	return msg, nil
}
