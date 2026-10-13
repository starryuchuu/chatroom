package server

import (
	"chatroom/internal/handlers"
	"net"
)

func sendHistory(conn net.Conn, username string, key []byte) error {
	return handlers.SendHistory(conn, username, key, "", "", 0)
}
