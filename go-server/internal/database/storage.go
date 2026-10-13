package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// storage v1 is deliberately identical to storage.py; it does not change the wire protocol.
type storageCodec struct {
	aead   cipher.AEAD
	lookup []byte
}

var storage *storageCodec

const storageCheck = "chatroom storage v1"

func deriveStorageKey(key []byte, label string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))
	return h.Sum(nil)
}
func newStorage(key []byte) (*storageCodec, error) {
	if len(key) != 32 {
		return nil, errors.New("storage key must contain exactly 32 bytes")
	}
	block, err := aes.NewCipher(deriveStorageKey(key, "chatroom/storage/v1/encryption"))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &storageCodec{aead, deriveStorageKey(key, "chatroom/storage/v1/lookup")}, nil
}
func storageContext(parts ...string) []byte {
	data := []byte("chatroom-storage-v1\x00")
	for _, part := range parts {
		data = append(data, []byte(strconv.Itoa(len([]byte(part)))+":"+part)...)
	}
	return data
}
func (s *storageCodec) seal(value string, parts ...string) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	data := s.aead.Seal(nonce, nonce, []byte(value), storageContext(parts...))
	return "enc1:" + base64.StdEncoding.EncodeToString(data), nil
}
func (s *storageCodec) open(value string, parts ...string) (string, error) {
	if !strings.HasPrefix(value, "enc1:") {
		return "", errors.New("unencrypted or invalid storage field")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(value[5:])
	if err != nil {
		return "", err
	}
	n := s.aead.NonceSize()
	if len(data) < n+s.aead.Overhead() {
		return "", errors.New("truncated storage field")
	}
	plain, err := s.aead.Open(nil, data[:n], data[n:], storageContext(parts...))
	return string(plain), err
}
func (s *storageCodec) token(name string) string {
	h := hmac.New(sha256.New, s.lookup)
	h.Write([]byte(name))
	return "u1:" + hex.EncodeToString(h.Sum(nil))
}

type storageExecutor interface {
	Exec(string, ...interface{}) (sql.Result, error)
}

func (s *storageCodec) putName(db storageExecutor, name string) (string, error) {
	token := s.token(name)
	value, err := s.seal(name, "names", token)
	if err != nil {
		return "", err
	}
	_, err = db.Exec("INSERT OR IGNORE INTO storage_names(token,value) VALUES(?,?)", token, value)
	return token, err
}
func (s *storageCodec) name(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	var encoded string
	if err := DB.QueryRow("SELECT value FROM storage_names WHERE token=?", token).Scan(&encoded); err != nil {
		return "", err
	}
	name, err := s.open(encoded, "names", token)
	if err != nil {
		return "", err
	}
	if !hmac.Equal([]byte(s.token(name)), []byte(token)) {
		return "", errors.New("invalid storage identity")
	}
	return name, nil
}
func readStorageKey(path string, encrypted bool) ([]byte, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if encrypted {
			return nil, errors.New("storage key is missing; restore the original key before starting")
		}
		data = make([]byte, 32)
		if _, err = rand.Read(data); err != nil {
			return nil, err
		}
		file, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			return nil, createErr
		}
		_, err = file.Write(data)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil && runtime.GOOS != "windows" {
			directory, openErr := os.Open(filepath.Dir(path))
			if openErr != nil {
				err = openErr
			} else {
				err = directory.Sync()
				directory.Close()
			}
		}
		if err != nil {
			os.Remove(path)
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(data) != 32 {
		return nil, errors.New("storage key must contain exactly 32 bytes")
	}
	if err = os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return data, nil
}
func initializeStorage(path string) error {
	for _, stmt := range []string{
		"CREATE TABLE IF NOT EXISTS storage_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS storage_names(token TEXT PRIMARY KEY,value TEXT NOT NULL)",
	} {
		if _, err := DB.Exec(stmt); err != nil {
			return err
		}
	}
	rows, err := DB.Query("SELECT key,value FROM storage_meta")
	if err != nil {
		return err
	}
	meta := map[string]string{}
	for rows.Next() {
		var k, v string
		if err = rows.Scan(&k, &v); err != nil {
			rows.Close()
			return err
		}
		meta[k] = v
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	version := meta["version"]
	if version != "" && version != "1" {
		return errors.New("unsupported storage version")
	}
	if version == "" {
		var names int
		if err = DB.QueryRow("SELECT COUNT(*) FROM storage_names").Scan(&names); err != nil {
			return err
		}
		if len(meta) != 0 || names != 0 {
			return errors.New("invalid storage metadata; startup stopped")
		}
	}
	keyPath := os.Getenv("CHATROOM_STORAGE_KEY_FILE")
	if keyPath == "" {
		keyPath = path + ".key"
	}
	key, err := readStorageKey(keyPath, version == "1")
	if err != nil {
		return err
	}
	codec, err := newStorage(key)
	if err != nil {
		return err
	}
	if version == "1" {
		check, err := codec.open(meta["key_check"], "meta", "key_check")
		if err != nil || check != storageCheck {
			return errors.New("storage key mismatch or corrupt database; startup stopped")
		}
	} else {
		if err = leaveStorageWAL(); err != nil {
			return err
		}
		tx, err := DB.Begin()
		if err != nil {
			return err
		}
		if err = migrateStorage(tx, codec); err != nil {
			tx.Rollback()
			return err
		}
		check, err := codec.seal(storageCheck, "meta", "key_check")
		if err != nil {
			tx.Rollback()
			return err
		}
		for k, v := range map[string]string{"version": "1", "key_check": check, "cleanup_pending": "1"} {
			if _, err = tx.Exec("INSERT INTO storage_meta VALUES(?,?)", k, v); err != nil {
				tx.Rollback()
				return err
			}
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		meta["cleanup_pending"] = "1"
	}
	if meta["cleanup_pending"] == "1" {
		if err = leaveStorageWAL(); err != nil {
			return err
		}
		if _, err = DB.Exec("VACUUM"); err != nil {
			return err
		}
		if _, err = DB.Exec("UPDATE storage_meta SET value='0' WHERE key='cleanup_pending'"); err != nil {
			return err
		}
	}
	storage = codec
	return nil
}
func leaveStorageWAL() error {
	var busy, log, checkpoint int
	if err := DB.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &checkpoint); err != nil {
		return err
	}
	if busy != 0 {
		return errors.New("database is busy; storage cleanup stopped")
	}
	var mode string
	if err := DB.QueryRow("PRAGMA journal_mode=DELETE").Scan(&mode); err != nil {
		return err
	}
	if mode != "delete" {
		return errors.New("cannot leave WAL mode for storage migration")
	}
	return nil
}

type migrationSpec struct {
	table                   string
	columns, names, secrets []string
}

func storageString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	default:
		return fmt.Sprint(v)
	}
}
func messageStorageContext(id int64, kind, from, to, gid string) []string {
	return []string{"messages", "message", strconv.FormatInt(id, 10), kind, from, to, gid}
}
func migrateStorage(tx *sql.Tx, s *storageCodec) error {
	specs := []migrationSpec{
		{"users", []string{"username", "password"}, []string{"username"}, []string{"password"}},
		{"friends", []string{"user", "friend"}, []string{"user", "friend"}, nil},
		{"groups", []string{"gid", "group_name", "owner", "members", "created_at"}, nil, []string{"group_name", "owner", "members", "created_at"}},
		{"messages", []string{"id", "chat_type", "from_user", "to_user", "gid", "message", "timestamp"}, []string{"from_user", "to_user"}, []string{"message", "timestamp"}},
		{"pending_friend_requests", []string{"requester", "target"}, []string{"requester", "target"}, nil},
		{"pending_group_invites", []string{"gid", "target", "inviter"}, []string{"target", "inviter"}, nil},
	}
	for _, spec := range specs {
		var after int64
		for {
			rows, err := tx.Query("SELECT rowid,"+strings.Join(spec.columns, ",")+" FROM "+spec.table+" WHERE rowid>? ORDER BY rowid LIMIT 256", after)
			if err != nil {
				return err
			}
			batch := [][]interface{}{}
			for rows.Next() {
				values := make([]interface{}, len(spec.columns)+1)
				dest := make([]interface{}, len(values))
				for i := range values {
					dest[i] = &values[i]
				}
				if err = rows.Scan(dest...); err != nil {
					rows.Close()
					return err
				}
				batch = append(batch, values)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			if len(batch) == 0 {
				break
			}
			for _, row := range batch {
				after = row[0].(int64)
				values := map[string]interface{}{}
				for i, c := range spec.columns {
					values[c] = row[i+1]
				}
				for _, c := range spec.names {
					if values[c] != nil && storageString(values[c]) != "" {
						token, err := s.putName(tx, storageString(values[c]))
						if err != nil {
							return err
						}
						values[c] = token
					}
				}
				for _, c := range spec.secrets {
					key := storageString(values["id"])
					if spec.table == "users" {
						key = storageString(values["username"])
					}
					if spec.table == "groups" {
						key = storageString(values["gid"])
					}
					parts := []string{spec.table, c, key}
					if spec.table == "messages" && c == "message" {
						parts = messageStorageContext(values["id"].(int64), storageString(values["chat_type"]), storageString(values["from_user"]), storageString(values["to_user"]), storageString(values["gid"]))
					}
					sealed, err := s.seal(storageString(values[c]), parts...)
					if err != nil {
						return err
					}
					values[c] = sealed
				}
				changed := append(append([]string{}, spec.names...), spec.secrets...)
				sets := []string{}
				args := []interface{}{}
				for _, c := range changed {
					sets = append(sets, c+"=?")
					args = append(args, values[c])
				}
				args = append(args, after)
				if _, err = tx.Exec("UPDATE "+spec.table+" SET "+strings.Join(sets, ",")+" WHERE rowid=?", args...); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
