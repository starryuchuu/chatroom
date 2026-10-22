package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"

	"chatroom/internal/e2ee"
	"chatroom/internal/opaqueauth"
)

const opaqueDisabledPassword = "!opaque-v1!"

var opaqueSetupMu sync.Mutex

type OpaqueAccount struct {
	Record     string
	Backup     map[string]interface{}
	Generation int64
}

func decodeOpaqueBackup(value string, document *map[string]interface{}) error {
	if len(value) > opaqueauth.MaxMessageBytes || json.Unmarshal([]byte(value), document) != nil || *document == nil {
		return errors.New("invalid encrypted identity backup")
	}
	return nil
}

func upgradeOpaqueSchema() error {
	for _, statement := range []string{
		"CREATE TABLE IF NOT EXISTS opaque_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS opaque_accounts(username TEXT PRIMARY KEY,record TEXT NOT NULL,backup TEXT NOT NULL,generation INTEGER NOT NULL)",
	} {
		if _, err := DB.Exec(statement); err != nil {
			return err
		}
	}
	_, err := GetOrCreateOpaqueSetup(context.Background())
	return err
}

// GetOrCreateOpaqueSetup persists the setup under storage encryption. Existing
// accounts make missing setup a fatal condition; it is never silently rotated.
func GetOrCreateOpaqueSetup(ctx context.Context) (string, error) {
	opaqueSetupMu.Lock()
	defer opaqueSetupMu.Unlock()
	var encoded string
	err := DB.QueryRow("SELECT value FROM opaque_meta WHERE key='setup_v1'").Scan(&encoded)
	if err == nil {
		return storage.open(encoded, "opaque_meta", "setup_v1")
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	var count int
	if err := DB.QueryRow("SELECT COUNT(*) FROM opaque_accounts").Scan(&count); err != nil {
		return "", err
	}
	if count != 0 {
		return "", errors.New("OPAQUE setup missing; restore the original database")
	}
	generated, err := opaqueauth.Call(ctx, map[string]interface{}{"op": "server_setup"})
	if err != nil {
		return "", err
	}
	setup, ok := generated["setup"].(string)
	if !ok || setup == "" {
		return "", opaqueauth.ErrAuthentication
	}
	encoded, err = storage.seal(setup, "opaque_meta", "setup_v1")
	if err != nil {
		return "", err
	}
	if _, err = DB.Exec("INSERT OR IGNORE INTO opaque_meta(key,value) VALUES('setup_v1',?)", encoded); err != nil {
		return "", err
	}
	if err = DB.QueryRow("SELECT value FROM opaque_meta WHERE key='setup_v1'").Scan(&encoded); err != nil {
		return "", err
	}
	return storage.open(encoded, "opaque_meta", "setup_v1")
}

func GetOpaqueAccount(username string) (*OpaqueAccount, error) {
	token := storage.token(username)
	var record, backup string
	var generation int64
	err := DB.QueryRow("SELECT record,backup,generation FROM opaque_accounts WHERE username=?", token).Scan(&record, &backup, &generation)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	record, err = storage.open(record, "opaque_accounts", "record", token)
	if err != nil {
		return nil, err
	}
	backup, err = storage.open(backup, "opaque_accounts", "backup", token)
	if err != nil {
		return nil, err
	}
	var document map[string]interface{}
	if err := decodeOpaqueBackup(backup, &document); err != nil {
		return nil, err
	}
	if generation < 1 {
		return nil, errors.New("invalid OPAQUE generation")
	}
	return &OpaqueAccount{Record: record, Backup: document, Generation: generation}, nil
}

func opaqueFields(username, record string, backup map[string]interface{}) (string, string, string, error) {
	token := storage.token(username)
	encodedRecord, err := storage.seal(record, "opaque_accounts", "record", token)
	if err != nil {
		return "", "", "", err
	}
	canonical, err := e2ee.Canonical(backup)
	if err != nil {
		return "", "", "", err
	}
	encodedBackup, err := storage.seal(string(canonical), "opaque_accounts", "backup", token)
	return token, encodedRecord, encodedBackup, err
}

func opaqueContext(contexts []context.Context) context.Context {
	if len(contexts) == 1 && contexts[0] != nil {
		return contexts[0]
	}
	return context.Background()
}

func CreateOpaqueAccount(username, record string, backup map[string]interface{}, contexts ...context.Context) error {
	ctx := opaqueContext(contexts)
	if err := ctx.Err(); err != nil {
		return err
	}
	token, encodedRecord, encodedBackup, err := opaqueFields(username, record, backup)
	if err != nil {
		return err
	}
	password, err := storage.seal(opaqueDisabledPassword, "users", "password", token)
	if err != nil {
		return err
	}
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = storage.putName(tx, username); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO users(username,password) VALUES(?,?)", token, password); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO opaque_accounts(username,record,backup,generation) VALUES(?,?,?,1)", token, encodedRecord, encodedBackup); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

// CheckOpaqueMigration verifies only an unmigrated account and returns its exact
// encrypted password version for a compare-and-swap at final registration.
func CheckOpaqueMigration(username, password string) (string, error) {
	account, err := GetOpaqueAccount(username)
	if err != nil {
		return "", err
	}
	if account != nil {
		return "", opaqueauth.ErrAuthentication
	}
	token := storage.token(username)
	var encoded string
	if err := DB.QueryRow("SELECT password FROM users WHERE username=?", token).Scan(&encoded); err != nil {
		return "", opaqueauth.ErrAuthentication
	}
	plain, err := storage.open(encoded, "users", "password", token)
	if err != nil {
		return "", err
	}
	valid, err := verifyPassword(password, plain, username)
	if err != nil {
		return "", err
	}
	if !valid {
		return "", opaqueauth.ErrAuthentication
	}
	return encoded, nil
}

func MigrateOpaqueAccount(username, expectedLegacy, record string, backup map[string]interface{}, contexts ...context.Context) error {
	ctx := opaqueContext(contexts)
	if err := ctx.Err(); err != nil {
		return err
	}
	token, encodedRecord, encodedBackup, err := opaqueFields(username, record, backup)
	if err != nil {
		return err
	}
	password, err := storage.seal(opaqueDisabledPassword, "users", "password", token)
	if err != nil {
		return err
	}
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE users SET password=? WHERE username=? AND password=? AND NOT EXISTS(SELECT 1 FROM opaque_accounts WHERE username=?)", password, token, expectedLegacy, token)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return opaqueauth.ErrAuthentication
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO opaque_accounts(username,record,backup,generation) VALUES(?,?,?,1)", token, encodedRecord, encodedBackup); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

func ReplaceOpaqueAccount(username string, expected int64, record string, backup map[string]interface{}, contexts ...context.Context) error {
	ctx := opaqueContext(contexts)
	if err := ctx.Err(); err != nil {
		return err
	}
	token, encodedRecord, encodedBackup, err := opaqueFields(username, record, backup)
	if err != nil {
		return err
	}
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE opaque_accounts SET record=?,backup=?,generation=generation+1 WHERE username=? AND generation=?", encodedRecord, encodedBackup, token, expected)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return opaqueauth.ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return tx.Commit()
}
