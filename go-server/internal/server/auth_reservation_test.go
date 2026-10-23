package server

import (
	chatcrypto "chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/handlers"
	"chatroom/internal/opaqueauth"
	"chatroom/internal/protocol"
	"chatroom/internal/types"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

type reservationTestAddress string

func (a reservationTestAddress) Network() string { return "test" }
func (a reservationTestAddress) String() string  { return string(a) }

type reservationTestConn struct {
	net.Conn
	address net.Addr
}

func (c *reservationTestConn) RemoteAddr() net.Addr { return c.address }

type reservedAuthResult struct {
	username string
	err      error
}

func startReservedAuthentication(t *testing.T, manager types.ClientManager) (net.Conn, net.Conn, <-chan reservedAuthResult) {
	t.Helper()
	peer, raw := net.Pipe()
	remote := &reservationTestConn{Conn: raw, address: reservationTestAddress(t.Name())}
	deadline := time.Now().Add(15 * time.Second)
	peer.SetDeadline(deadline)
	remote.SetDeadline(deadline)
	results := make(chan reservedAuthResult, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		name, err := handlers.HandleAuth(remote, make([]byte, 16), manager, handlers.AuthOptions{ServerID: strings.Repeat("a", 64), Deadline: deadline, KeepReservation: true})
		results <- reservedAuthResult{name, err}
	}()
	t.Cleanup(func() {
		peer.Close()
		remote.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("authentication worker did not release after cancellation")
		}
	})
	return peer, remote, results
}

func waitReservedAuthentication(t *testing.T, results <-chan reservedAuthResult) reservedAuthResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("authentication did not finish")
		return reservedAuthResult{}
	}
}

func sendReservationLegacy(t *testing.T, peer net.Conn, password string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"from": "alice", "password": password})
	encrypted, err := chatcrypto.EncryptMessage(string(body), make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.SendMsg(peer, map[string]interface{}{"type": "encrypted_login", "data": encrypted}); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationReservationSurvivesProofUntilOnlinePublication(t *testing.T) {
	setupServer(t)
	manager := NewClientManager()
	peer, remote, results := startReservedAuthentication(t, manager)
	sendReservationLegacy(t, peer, "secret123")
	result := waitReservedAuthentication(t, results)
	if result.err != nil || result.username != "alice" {
		t.Fatal("valid legacy authentication failed")
	}
	defer manager.ReleaseAuthentication("alice", remote)
	if manager.ReserveAuthentication("alice", peer) {
		t.Fatal("proof-to-publication window permitted another authentication")
	}
	if manager.AddClient("alice", peer, nil, nil) {
		t.Fatal("a different connection consumed the reservation")
	}
	if !manager.AddClient("alice", remote, nil, nil) {
		t.Fatal("owning connection could not atomically publish")
	}
	if len(manager.GetOnlineUsernames()) != 0 {
		t.Fatal("reserved session became visible before activation")
	}
	if !manager.ActivateClient("alice", remote) {
		t.Fatal("could not activate published session")
	}
	manager.ReleaseAuthentication("alice", peer)
	if !manager.IsUserOnline("alice") {
		t.Fatal("unrelated cleanup removed the winning session")
	}
	manager.RemoveClient("alice", remote)
	if !manager.ReserveAuthentication("alice", peer) {
		t.Fatal("closed session left a reservation behind")
	}
	manager.ReleaseAuthentication("alice", peer)
}

func TestFailedLegacyAuthenticationReleasesReservation(t *testing.T) {
	setupServer(t)
	manager := NewClientManager()
	peer, _, results := startReservedAuthentication(t, manager)
	sendReservationLegacy(t, peer, "synthetic-wrong-password")
	reply, err := protocol.RecvMsg(peer)
	if err != nil || reply["success"] != false {
		t.Fatal("wrong password was not rejected")
	}
	if result := waitReservedAuthentication(t, results); result.err == nil {
		t.Fatal("failed authentication returned success")
	}
	if !manager.ReserveAuthentication("alice", peer) {
		t.Fatal("wrong password leaked the reservation")
	}
	manager.ReleaseAuthentication("alice", peer)
}

func TestMigrationReservationBlocksLegacyLoginAndReleasesOnCancel(t *testing.T) {
	setupServer(t)
	manager := NewClientManager()
	peer, _, results := startReservedAuthentication(t, manager)
	start, err := opaqueauth.Call(context.Background(), map[string]interface{}{"op": "registration_start", "password": "synthetic-upgraded-password"})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := chatcrypto.EncryptMessage(`{"password":"secret123"}`, make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.SendMsg(peer, map[string]interface{}{"type": "opaque_migrate_start", "from": "alice", "request": start["request"], "legacy_data": legacy}); err != nil {
		t.Fatal(err)
	}
	challenge, err := protocol.RecvMsg(peer)
	if err != nil || challenge["type"] != "opaque_migrate_challenge" {
		t.Fatal("migration did not reach its reserved challenge")
	}
	competing, _, competingResult := startReservedAuthentication(t, manager)
	sendReservationLegacy(t, competing, "secret123")
	rejected, err := protocol.RecvMsg(competing)
	if err != nil || rejected["success"] != false {
		t.Fatal("legacy authentication raced the migration")
	}
	if result := waitReservedAuthentication(t, competingResult); result.err == nil {
		t.Fatal("competing legacy login returned success")
	}
	valid, err := database.ValidateUser("alice", "secret123")
	if err != nil || !valid {
		t.Fatal("blocked login unexpectedly changed legacy credentials")
	}
	peer.Close()
	if result := waitReservedAuthentication(t, results); result.err == nil {
		t.Fatal("cancelled migration returned success")
	}
	account, err := database.GetOpaqueAccount("alice")
	if err != nil || account != nil {
		t.Fatal("cancelled migration changed its account")
	}
	if !manager.ReserveAuthentication("alice", competing) {
		t.Fatal("cancelled migration leaked its reservation")
	}
	manager.ReleaseAuthentication("alice", competing)
}

func invokeReservationOpaque(t *testing.T, request map[string]interface{}) map[string]interface{} {
	t.Helper()
	result, err := opaqueauth.Call(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func createReservationOpaqueAccount(t *testing.T) (string, string, string) {
	t.Helper()
	username, password, serverID := "opaque-fixture", "synthetic-opaque-password", strings.Repeat("a", 64)
	setup, err := database.GetOrCreateOpaqueSetup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	registration := invokeReservationOpaque(t, map[string]interface{}{"op": "registration_start", "password": password})
	response := invokeReservationOpaque(t, map[string]interface{}{"op": "registration_respond", "setup": setup, "username": username, "server_id": serverID, "request": registration["request"]})
	record := invokeReservationOpaque(t, map[string]interface{}{"op": "registration_finish", "password": password, "state": registration["state"], "response": response["response"], "username": username, "server_id": serverID})
	if err := database.CreateOpaqueAccount(username, record["record"].(string), map[string]interface{}{"v": 1}); err != nil {
		t.Fatal(err)
	}
	return username, password, serverID
}

func TestCancelledOpaqueLoginDoesNotReserveBeforeProof(t *testing.T) {
	setupServer(t)
	manager := NewClientManager()
	username, password, _ := createReservationOpaqueAccount(t)
	peer, _, results := startReservedAuthentication(t, manager)
	login := invokeReservationOpaque(t, map[string]interface{}{"op": "login_start", "password": password})
	if err := protocol.SendMsg(peer, map[string]interface{}{"type": "opaque_login_start", "from": username, "request": login["request"]}); err != nil {
		t.Fatal(err)
	}
	challenge, err := protocol.RecvMsg(peer)
	if err != nil || challenge["type"] != "opaque_login_challenge" {
		t.Fatal("login did not reach its challenge")
	}
	if !manager.ReserveAuthentication(username, peer) {
		t.Fatal("OPAQUE start reserved an account before proving credentials")
	}
	manager.ReleaseAuthentication(username, peer)
	peer.Close()
	if result := waitReservedAuthentication(t, results); result.err == nil {
		t.Fatal("cancelled login returned success")
	}
	if !manager.ReserveAuthentication(username, peer) {
		t.Fatal("cancelled OPAQUE login leaked its reservation")
	}
	manager.ReleaseAuthentication(username, peer)
}

func TestStalledOpaqueChallengeCannotBlockProvenLogin(t *testing.T) {
	setupServer(t)
	manager := NewClientManager()
	username, password, serverID := createReservationOpaqueAccount(t)
	stalled, _, stalledResult := startReservedAuthentication(t, manager)
	unknownPasswordStart := invokeReservationOpaque(t, map[string]interface{}{"op": "login_start", "password": "synthetic-unknown-password"})
	if err := protocol.SendMsg(stalled, map[string]interface{}{"type": "opaque_login_start", "from": username, "request": unknownPasswordStart["request"]}); err != nil {
		t.Fatal(err)
	}
	if challenge, err := protocol.RecvMsg(stalled); err != nil || challenge["type"] != "opaque_login_challenge" {
		t.Fatal("unproven connection did not reach its challenge")
	}

	// Leave the first connection waiting for a proof it cannot provide. A
	// second connection with the real password must still authenticate.
	legitimate, remote, results := startReservedAuthentication(t, manager)
	start := invokeReservationOpaque(t, map[string]interface{}{"op": "login_start", "password": password})
	if err := protocol.SendMsg(legitimate, map[string]interface{}{"type": "opaque_login_start", "from": username, "request": start["request"]}); err != nil {
		t.Fatal(err)
	}
	challenge, err := protocol.RecvMsg(legitimate)
	if err != nil || challenge["type"] != "opaque_login_challenge" {
		t.Fatal("stalled connection blocked the legitimate challenge")
	}
	finish := invokeReservationOpaque(t, map[string]interface{}{"op": "login_finish", "password": password, "state": start["state"], "response": challenge["response"], "username": username, "server_id": serverID})
	if err := protocol.SendMsg(legitimate, map[string]interface{}{"type": "opaque_login_finish", "finalization": finish["finalization"]}); err != nil {
		t.Fatal(err)
	}
	result := waitReservedAuthentication(t, results)
	if result.err != nil || result.username != username {
		t.Fatal("stalled unproven connection blocked valid authentication")
	}
	defer manager.ReleaseAuthentication(username, remote)
	if manager.ReserveAuthentication(username, stalled) {
		t.Fatal("verified proof did not retain its publication reservation")
	}
	if !manager.AddClient(username, remote, nil, nil) || !manager.ActivateClient(username, remote) {
		t.Fatal("verified login could not publish its session")
	}
	defer manager.RemoveClient(username, remote)
	stalled.Close()
	if result := waitReservedAuthentication(t, stalledResult); result.err == nil {
		t.Fatal("unproven cancelled login returned success")
	}
	if !manager.IsUserOnline(username) {
		t.Fatal("unproven connection cleanup removed the verified session")
	}
}
