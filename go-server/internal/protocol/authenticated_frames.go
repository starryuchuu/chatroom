package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
)

type frameAuth struct {
	sendKey, recvKey []byte
	sendSeq, recvSeq uint64
}

func directionalKey(key []byte, direction string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("chatroom/frame/v2/" + direction))
	return mac.Sum(nil)
}

// EnableAuthentication is used exactly once after RSA key establishment.
// Counters are independent per direction; frames are signed in writer order.
func EnableAuthentication(conn net.Conn, key []byte, server bool) {
	c := conn.(*Conn)
	clientKey, serverKey := directionalKey(key, "client"), directionalKey(key, "server")
	auth := &frameAuth{sendKey: clientKey, recvKey: serverKey}
	if server {
		auth.sendKey, auth.recvKey = serverKey, clientKey
	}
	c.stateMu.Lock()
	c.auth = auth
	c.stateMu.Unlock()
}

func (a *frameAuth) encode(payload []byte) ([]byte, error) {
	if len(payload) > MaxMessageLen {
		return nil, fmt.Errorf("message too large")
	}
	frame := make([]byte, 8+len(payload), 8+len(payload)+sha256.Size)
	binary.BigEndian.PutUint64(frame, a.sendSeq)
	copy(frame[8:], payload)
	mac := hmac.New(sha256.New, a.sendKey)
	mac.Write(frame)
	frame = append(frame, mac.Sum(nil)...)
	a.sendSeq++
	return frame, nil
}

func (a *frameAuth) decode(frame []byte) ([]byte, error) {
	if len(frame) < FrameOverhead {
		return nil, fmt.Errorf("unauthenticated frame rejected")
	}
	authenticated, signature := frame[:len(frame)-sha256.Size], frame[len(frame)-sha256.Size:]
	mac := hmac.New(sha256.New, a.recvKey)
	mac.Write(authenticated)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, fmt.Errorf("frame authentication failed")
	}
	if binary.BigEndian.Uint64(authenticated[:8]) != a.recvSeq {
		return nil, fmt.Errorf("replayed or out-of-order frame rejected")
	}
	a.recvSeq++
	return authenticated[8:], nil
}
