package handlers

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/opaqueauth"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestOpaqueMigrationRequiresOtherSessionToDisconnect(t *testing.T) {
	manager := setupHandlers(t)
	manager.AddClient("alice", &recordConn{}, nil, nil)
	start, err := opaqueauth.Call(context.Background(), map[string]interface{}{"op": "registration_start", "password": "synthetic-new-password"})
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 16)
	legacy, err := crypto.EncryptMessage(`{"password":"unused-password"}`, key)
	if err != nil {
		t.Fatal(err)
	}
	conn := &recordConn{}
	user, err := handleOpaque(conn, key, manager, map[string]interface{}{"type": "opaque_migrate_start", "from": "alice", "request": start["request"], "legacy_data": legacy}, strings.Repeat("a", 64), time.Now().Add(10*time.Second))
	if user != "" || !errors.Is(err, errOpaqueHandled) {
		t.Fatal("online account migration was not stopped")
	}
	if conn.result(t, "login_result")["success"] != false {
		t.Fatal("online migration reported success")
	}
	account, err := database.GetOpaqueAccount("alice")
	if err != nil || account != nil {
		t.Fatal("rejected online migration modified account")
	}
}
