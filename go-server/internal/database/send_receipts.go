package database

import (
	"chatroom/internal/e2ee"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
)

var receiptKey = regexp.MustCompile(`^[0-9a-f]{32}$`)

func ValidReceiptKey(key string) bool { return receiptKey.MatchString(key) }

func receiptToken(key string) string { return storage.token("chatroom/send/v1/request\x00" + key) }

type ChatSave struct {
	ID        int64
	Duplicate bool
	Timestamp string
}

// The message and its durable idempotency record share a single transaction.
func SaveChatWithReceipt(kind, sender, recipient, gid, body, timestamp string, encrypted bool, key string) (ChatSave, error) {
	saved := ChatSave{Timestamp: timestamp}
	if key != "" && !ValidReceiptKey(key) {
		return saved, errors.New("invalid send receipt key")
	}
	tx, err := DB.Begin()
	if err != nil {
		return saved, err
	}
	defer tx.Rollback()
	who, token, fingerprint := "", "", ""
	target := recipient
	if kind == "group" {
		target = gid
	}
	if key != "" {
		var content interface{} = body
		if encrypted {
			if err = json.Unmarshal([]byte(body), &content); err != nil {
				return saved, err
			}
		}
		encoded, err := e2ee.Canonical([]interface{}{kind, recipient, gid, encrypted, content})
		if err != nil {
			return saved, err
		}
		who, token = storage.token(sender), receiptToken(key)
		fingerprint = storage.token("chatroom/send/v1/payload\x00" + string(encoded))
		var previous, at string
		err = tx.QueryRow(`SELECT r.payload_hash,r.message_id,m.timestamp FROM send_receipts r JOIN messages m ON m.id=r.message_id WHERE r.sender=? AND r.receipt_key=?`, who, token).Scan(&previous, &saved.ID, &at)
		if err == nil {
			if previous != fingerprint {
				return ChatSave{}, errors.New("send receipt content conflict")
			}
			saved.Timestamp, err = storage.open(at, "messages", "timestamp", strconv.FormatInt(saved.ID, 10))
			saved.Duplicate = true
			return saved, err
		}
		if err != sql.ErrNoRows {
			return saved, err
		}
	}
	saved.ID, err = insertMessage(tx, kind, sender, recipient, gid, body, timestamp, encrypted)
	if err != nil {
		return saved, err
	}
	if key != "" {
		if _, err = tx.Exec(`INSERT INTO send_receipts VALUES(?,?,?,?,?,?)`, who, token, kind, storage.token(target), fingerprint, saved.ID); err != nil {
			return saved, err
		}
	}
	return saved, tx.Commit()
}

func LookupSendReceipt(sender, key, kind, target string) (ChatSave, error) {
	var saved ChatSave
	if !ValidReceiptKey(key) {
		return saved, errors.New("invalid send receipt key")
	}
	var at string
	err := DB.QueryRow(`SELECT r.message_id,m.timestamp FROM send_receipts r JOIN messages m ON m.id=r.message_id WHERE r.sender=? AND r.receipt_key=? AND r.chat_type=? AND r.target=?`, storage.token(sender), receiptToken(key), kind, storage.token(target)).Scan(&saved.ID, &at)
	if err == sql.ErrNoRows {
		return saved, nil
	}
	if err != nil {
		return saved, err
	}
	saved.Timestamp, err = storage.open(at, "messages", "timestamp", strconv.FormatInt(saved.ID, 10))
	return saved, err
}
