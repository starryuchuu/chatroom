package database

import (
	"database/sql"
	"errors"
)

// upgradeE2EESchema runs only after the existing storage key has been validated.
// Version-1 storage and its authenticated field contexts remain unchanged.
func upgradeE2EESchema() error {
	rows, err := DB.Query("PRAGMA table_info(messages)")
	if err != nil {
		return err
	}
	hasFlag := false
	for rows.Next() {
		var cid, notNull, primary int
		var name, kind string
		var defaultValue sql.NullString
		if err = rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
			rows.Close()
			return err
		}
		if name == "e2ee" {
			hasFlag = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if !hasFlag {
		if _, err = tx.Exec("ALTER TABLE messages ADD COLUMN e2ee INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("CREATE TABLE IF NOT EXISTS e2ee_identities(username TEXT PRIMARY KEY,identity TEXT NOT NULL)"); err != nil {
		return err
	}
	return tx.Commit()
}

// GetE2EEIdentity returns the immutable public identity, or an empty string when
// this account has not enabled E2EE. No private keys enter this database.
func GetE2EEIdentity(username string) (string, error) {
	token := storage.token(username)
	var ciphertext string
	err := DB.QueryRow("SELECT identity FROM e2ee_identities WHERE username=?", token).Scan(&ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return storage.open(ciphertext, "e2ee_identities", "identity", token)
}

// PublishE2EEIdentity atomically registers the first canonical public identity.
// Subsequent publication can confirm the same identity but cannot replace it.
func PublishE2EEIdentity(username, identity string) (string, error) {
	if username == "" || identity == "" {
		return "", errors.New("端到端加密身份不能为空")
	}
	tx, err := DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	token, err := storage.putName(tx, username)
	if err != nil {
		return "", err
	}
	var ciphertext string
	err = tx.QueryRow("SELECT identity FROM e2ee_identities WHERE username=?", token).Scan(&ciphertext)
	if err == nil {
		current, err := storage.open(ciphertext, "e2ee_identities", "identity", token)
		if err != nil {
			return "", err
		}
		if current != identity {
			return current, errors.New("该账号已绑定其他端到端加密身份，请导入原密钥")
		}
		if err = tx.Commit(); err != nil {
			return "", err
		}
		return current, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	ciphertext, err = storage.seal(identity, "e2ee_identities", "identity", token)
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec("INSERT INTO e2ee_identities(username,identity) VALUES(?,?)", token, ciphertext); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return identity, nil
}
