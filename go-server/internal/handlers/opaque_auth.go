package handlers

import (
	"chatroom/internal/crypto"
	"chatroom/internal/database"
	"chatroom/internal/e2ee"
	"chatroom/internal/opaqueauth"
	"chatroom/internal/protocol"
	"chatroom/internal/types"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"time"
	"unicode/utf8"
)

var errOpaqueHandled = errors.New("OPAQUE operation completed")
var errOpaqueMigrationRequired = errors.New("OPAQUE migration required")

func opaqueField(msg map[string]interface{}, key string) (string, error) {
	value, ok := msg[key].(string)
	if !ok || value == "" || len(value) > opaqueauth.MaxMessageBytes {
		return "", opaqueauth.ErrAuthentication
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || base64.StdEncoding.EncodeToString(decoded) != value {
		return "", opaqueauth.ErrAuthentication
	}
	return value, nil
}

func opaqueStep(conn net.Conn, kind string) (map[string]interface{}, error) {
	msg, err := protocol.RecvMsg(conn)
	if err != nil {
		return nil, opaqueauth.ErrAuthentication
	}
	if msg["type"] != kind {
		return nil, opaqueauth.ErrAuthentication
	}
	return msg, nil
}

func opaqueOutput(result map[string]interface{}, key string) (string, error) {
	value, ok := result[key].(string)
	if !ok || value == "" {
		return "", opaqueauth.ErrAuthentication
	}
	return value, nil
}

func opaqueIdentity(username string) (interface{}, error) {
	encoded, err := database.GetE2EEIdentity(username)
	if err != nil {
		return nil, err
	}
	if encoded == "" {
		return nil, nil
	}
	return e2ee.ParseBundle(encoded)
}

func validOpaqueBackup(value interface{}, username, serverID string) (map[string]interface{}, error) {
	backup, ok := value.(map[string]interface{})
	if !ok || len(backup) != 7 || backup["kind"] != "opaque-identity" || backup["username"] != username || backup["server_id"] != serverID {
		return nil, opaqueauth.ErrAuthentication
	}
	version, ok := backup["v"].(float64)
	if !ok || version != 1 {
		return nil, opaqueauth.ErrAuthentication
	}
	for field, length := range map[string]int{"salt": 16, "nonce": 12, "data": 0} {
		text, err := opaqueField(backup, field)
		if err != nil {
			return nil, err
		}
		decoded, _ := base64.StdEncoding.DecodeString(text)
		if (length > 0 && len(decoded) != length) || (length == 0 && len(decoded) < 16) {
			return nil, opaqueauth.ErrAuthentication
		}
	}
	encoded, err := e2ee.Canonical(backup)
	if err != nil || len(encoded) > opaqueauth.MaxMessageBytes {
		return nil, opaqueauth.ErrAuthentication
	}
	return backup, nil
}

func opaqueRegisterResponse(ctx context.Context, setup, username, serverID, request string) (string, error) {
	result, err := opaqueauth.Call(ctx, map[string]interface{}{"op": "registration_respond", "setup": setup, "username": username, "server_id": serverID, "request": request})
	if err != nil {
		return "", err
	}
	return opaqueOutput(result, "response")
}

func opaqueFinalRecord(ctx context.Context, msg map[string]interface{}, username, serverID string) (string, map[string]interface{}, error) {
	record, err := opaqueField(msg, "record")
	if err != nil {
		return "", nil, err
	}
	backup, err := validOpaqueBackup(msg["backup"], username, serverID)
	if err != nil {
		return "", nil, err
	}
	result, err := opaqueauth.Call(ctx, map[string]interface{}{"op": "record_validate", "record": record})
	if err != nil {
		return "", nil, err
	}
	record, err = opaqueOutput(result, "record")
	return record, backup, err
}

// handleOpaque consumes exactly one complete exchange under the caller's shared
// authentication deadline and concurrency reservation. No secret is logged.
func handleOpaque(conn net.Conn, sessionKey []byte, manager types.ClientManager, msg map[string]interface{}, serverID string, deadline time.Time, keepReservations ...bool) (username string, resultErr error) {
	kind, _ := msg["type"].(string)
	resultType := "login_result"
	if kind == "opaque_register_start" {
		resultType = "register_result"
	}
	if kind == "opaque_change_start" {
		resultType = "opaque_change_result"
	}
	defer func() {
		if resultErr != nil && !errors.Is(resultErr, errRegistered) && !errors.Is(resultErr, errOpaqueHandled) && !errors.Is(resultErr, errOpaqueMigrationRequired) {
			protocol.SendMsg(conn, map[string]interface{}{"type": resultType, "success": false, "error": "认证失败，请检查凭据或重试"})
			resultErr = opaqueauth.ErrAuthentication
		}
	}()
	username, ok := msg["from"].(string)
	if !ok || !utf8.ValidString(username) || utf8.RuneCountInString(username) < 2 || utf8.RuneCountInString(username) > 20 {
		return "", opaqueauth.ErrAuthentication
	}
	keep := false
	reservedName := ""
	defer func() {
		if reservedName != "" && !keep {
			manager.ReleaseAuthentication(reservedName, conn)
		}
	}()
	reserveAccount := func() bool {
		if manager == nil || !manager.ReserveAuthentication(username, conn) {
			protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "账号正在登录、迁移或已在线，请先退出其他连接"})
			return false
		}
		reservedName = username
		return true
	}
	if kind == "opaque_migrate_start" && manager != nil && manager.IsUserOnline(username) {
		protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "迁移前请先退出该账号的其他连接"})
		return "", errOpaqueHandled
	}
	if raw, err := hex.DecodeString(serverID); err != nil || len(raw) != 32 || hex.EncodeToString(raw) != serverID {
		return "", opaqueauth.ErrAuthentication
	}
	request, err := opaqueField(msg, "request")
	if err != nil {
		return "", err
	}
	if deadline.IsZero() || !time.Now().Before(deadline) {
		return "", opaqueauth.ErrAuthentication
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	setup, err := database.GetOrCreateOpaqueSetup(ctx)
	if err != nil {
		return "", err
	}
	account, err := database.GetOpaqueAccount(username)
	if err != nil {
		return "", err
	}

	if kind == "opaque_register_start" || kind == "opaque_migrate_start" {
		var expectedLegacy string
		if kind == "opaque_register_start" {
			exists, err := database.UserExists(username)
			if err != nil || exists {
				return "", opaqueauth.ErrAuthentication
			}
		} else {
			if account != nil {
				return "", opaqueauth.ErrAuthentication
			}
			legacy, ok := msg["legacy_data"].(string)
			if !ok || len(legacy) > opaqueauth.MaxMessageBytes {
				return "", opaqueauth.ErrAuthentication
			}
			plaintext, err := crypto.DecryptMessage(legacy, sessionKey)
			if err != nil {
				return "", opaqueauth.ErrAuthentication
			}
			var credentials map[string]interface{}
			if json.Unmarshal([]byte(plaintext), &credentials) != nil {
				return "", opaqueauth.ErrAuthentication
			}
			password, ok := credentials["password"].(string)
			if !ok || utf8.RuneCountInString(password) < 6 || utf8.RuneCountInString(password) > 64 {
				return "", opaqueauth.ErrAuthentication
			}
			expectedLegacy, err = database.CheckOpaqueMigration(username, password)
			if err != nil {
				return "", err
			}
			// Verified legacy credentials reserve the account before any
			// challenge/commit, keeping competing logins out of the migration.
			if !reserveAccount() {
				return "", errOpaqueHandled
			}
			// Another migration may have committed during legacy verification
			// and disconnected before this reservation became available.
			current, err := database.GetOpaqueAccount(username)
			if err != nil || current != nil {
				return "", opaqueauth.ErrAuthentication
			}
		}
		response, err := opaqueRegisterResponse(ctx, setup, username, serverID, request)
		if err != nil {
			return "", err
		}
		challenge := map[string]interface{}{"type": "opaque_register_challenge", "response": response}
		finish := "opaque_register_finish"
		if kind == "opaque_migrate_start" {
			challenge["type"] = "opaque_migrate_challenge"
			finish = "opaque_migrate_finish"
			identity, err := opaqueIdentity(username)
			if err != nil {
				return "", err
			}
			challenge["e2ee_identity"] = identity
		}
		if err := protocol.SendMsg(conn, challenge); err != nil {
			return "", err
		}
		final, err := opaqueStep(conn, finish)
		if err != nil {
			return "", err
		}
		record, backup, err := opaqueFinalRecord(ctx, final, username, serverID)
		if err != nil {
			return "", err
		}
		if kind == "opaque_register_start" {
			if err := database.CreateOpaqueAccount(username, record, backup, ctx); err != nil {
				return "", err
			}
			if err := protocol.SendMsg(conn, map[string]interface{}{"type": "register_result", "success": true}); err != nil {
				return "", err
			}
			return "", errRegistered
		}
		if manager != nil && manager.IsUserOnline(username) {
			protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "error": "迁移前请先退出该账号的其他连接"})
			return "", errOpaqueHandled
		}
		if err := database.MigrateOpaqueAccount(username, expectedLegacy, record, backup, ctx); err != nil {
			return "", err
		}
		keep = len(keepReservations) == 1 && keepReservations[0]
		return username, nil
	}

	if kind != "opaque_login_start" && kind != "opaque_change_start" {
		return "", opaqueauth.ErrAuthentication
	}
	if account == nil {
		exists, err := database.UserExists(username)
		if err != nil {
			return "", err
		}
		if exists && kind == "opaque_login_start" {
			protocol.SendMsg(conn, map[string]interface{}{"type": "login_result", "success": false, "migration_required": true, "error": "此账号需要一次性迁移，请使用迁移旧账号"})
			return "", errOpaqueMigrationRequired
		}
	}
	var record interface{}
	if account != nil {
		record = account.Record
	}
	result, err := opaqueauth.Call(ctx, map[string]interface{}{"op": "login_respond", "setup": setup, "record": record, "username": username, "server_id": serverID, "request": request})
	if err != nil {
		return "", err
	}
	state, err := opaqueOutput(result, "state")
	if err != nil {
		return "", err
	}
	response, err := opaqueOutput(result, "response")
	if err != nil {
		return "", err
	}
	challengeType, finishType := "opaque_login_challenge", "opaque_login_finish"
	if kind == "opaque_change_start" {
		challengeType, finishType = "opaque_change_challenge", "opaque_change_finish"
	}
	if err := protocol.SendMsg(conn, map[string]interface{}{"type": challengeType, "response": response}); err != nil {
		return "", err
	}
	final, err := opaqueStep(conn, finishType)
	if err != nil {
		return "", err
	}
	finalization, err := opaqueField(final, "finalization")
	if err != nil {
		return "", err
	}
	if _, err = opaqueauth.Call(ctx, map[string]interface{}{"op": "login_verify", "state": state, "finalization": finalization}); err != nil {
		return "", err
	}
	if account == nil {
		return "", opaqueauth.ErrAuthentication
	}
	if kind == "opaque_login_start" {
		// A challenge is public; require its password proof before reserving
		// the account so abandoned starts cannot block a legitimate login.
		if !reserveAccount() {
			return "", errOpaqueHandled
		}
		current, err := database.GetOpaqueAccount(username)
		if err != nil || current == nil || current.Generation != account.Generation {
			return "", opaqueauth.ErrAuthentication
		}
		// The verified account remains reserved through online publication.
		keep = len(keepReservations) == 1 && keepReservations[0]
		return username, nil
	}
	identity, err := opaqueIdentity(username)
	if err != nil {
		return "", err
	}
	if err := protocol.SendMsg(conn, map[string]interface{}{"type": "opaque_change_verified", "backup": account.Backup, "generation": account.Generation, "e2ee_identity": identity}); err != nil {
		return "", err
	}
	next, err := opaqueStep(conn, "opaque_change_register_start")
	if err != nil {
		return "", err
	}
	request, err = opaqueField(next, "request")
	if err != nil {
		return "", err
	}
	response, err = opaqueRegisterResponse(ctx, setup, username, serverID, request)
	if err != nil {
		return "", err
	}
	if err := protocol.SendMsg(conn, map[string]interface{}{"type": "opaque_change_register_challenge", "response": response}); err != nil {
		return "", err
	}
	next, err = opaqueStep(conn, "opaque_change_register_finish")
	if err != nil {
		return "", err
	}
	generation, ok := next["generation"].(float64)
	if !ok || generation != float64(account.Generation) {
		return "", opaqueauth.ErrAuthentication
	}
	newRecord, backup, err := opaqueFinalRecord(ctx, next, username, serverID)
	if err != nil {
		return "", err
	}
	if err := database.ReplaceOpaqueAccount(username, account.Generation, newRecord, backup, ctx); err != nil {
		return "", err
	}
	if err := protocol.SendMsg(conn, map[string]interface{}{"type": "opaque_change_result", "success": true}); err != nil {
		return "", err
	}
	return "", errOpaqueHandled
}
