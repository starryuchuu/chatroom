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
const WriteTimeout = 5 * time.Second

// Conn serializes complete frames sent by concurrent handlers and broadcasts.
// Its lock belongs to the connection, so closed sessions need no global cleanup.
type Conn struct {
	net.Conn
	writeMu   sync.Mutex
	stateMu   sync.RWMutex
	outbox    chan []byte
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func WrapConn(conn net.Conn) *Conn {
	if wrapped, ok := conn.(*Conn); ok {
		return wrapped
	}
	return &Conn{Conn: conn, done: make(chan struct{})}
}

// EnableQueuedWrites is called after the synchronous successful login response.
// Mutation handlers enqueue immutable frames in commit order without network I/O.
func EnableQueuedWrites(conn net.Conn) {
	if c, ok := conn.(*Conn); ok {
		c.stateMu.Lock()
		if c.outbox == nil {
			c.outbox = make(chan []byte, 256)
			go c.writeLoop(c.outbox)
		}
		c.stateMu.Unlock()
	}
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *Conn) writeLoop(outbox <-chan []byte) {
	for {
		select {
		case <-c.done:
			return
		case frame := <-outbox:
			if err := writeFrame(c, frame); err != nil {
				c.Close()
				return
			}
		}
	}
}

// ValidateMessage checks the final serialized size before database persistence.
func ValidateMessage(msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(data) > MaxMessageLen {
		return fmt.Errorf("message too large: %d bytes (max: %d)", len(data), MaxMessageLen)
	}
	return nil
}

// SendMsg sends one length-prefixed JSON frame. Shared server connections must
// be wrapped once with WrapConn before being published to other goroutines.
func SendMsg(conn net.Conn, msg interface{}) error {
	return sendMsg(conn, msg, false)
}

// SendMsgWait provides bounded backpressure for history, outside mutation locks.
func SendMsgWait(conn net.Conn, msg interface{}) error {
	return sendMsg(conn, msg, true)
}

func sendMsg(conn net.Conn, msg interface{}, wait bool) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(data) > MaxMessageLen {
		return fmt.Errorf("message too large: %d bytes (max: %d)", len(data), MaxMessageLen)
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)
	if c, ok := conn.(*Conn); ok {
		c.stateMu.RLock()
		outbox := c.outbox
		c.stateMu.RUnlock()
		if outbox != nil {
			select {
			case <-c.done:
				return net.ErrClosed
			default:
			}
			if wait {
				timer := time.NewTimer(WriteTimeout)
				defer timer.Stop()
				select {
				case <-c.done:
					return net.ErrClosed
				case outbox <- frame:
					return nil
				case <-timer.C:
					c.Close()
					return fmt.Errorf("outgoing queue timeout")
				}
			}
			select {
			case <-c.done:
				return net.ErrClosed
			case outbox <- frame:
				return nil
			default:
				c.Close()
				return fmt.Errorf("outgoing queue full")
			}
		}
	}
	return writeFrame(conn, frame)
}

func writeFrame(conn net.Conn, frame []byte) error {
	if wrapped, ok := conn.(*Conn); ok {
		wrapped.writeMu.Lock()
		defer wrapped.writeMu.Unlock()
	}
	// Refresh inside the frame lock; a deadline set at connection establishment
	// expires even when a session remains active.
	if err := conn.SetWriteDeadline(time.Now().Add(WriteTimeout)); err != nil {
		return err
	}
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
