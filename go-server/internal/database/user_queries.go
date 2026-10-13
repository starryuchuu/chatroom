package database

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2 密码哈希参数
const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// hashPassword 使用 Argon2id + 随机盐生成可自描述哈希串。
// 使用随机盐，避免用用户名这类公开信息做盐导致可预计算攻击。
func hashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// verifyPassword 校验密码。
// 支持新格式（随机盐）；对旧版（username 作盐的裸哈希）做向后兼容。
func verifyPassword(password, encoded string, legacyUsername string) (bool, error) {
	if strings.HasPrefix(encoded, "$argon2id$") {
		parts := strings.Split(encoded, "$")
		if len(parts) != 6 || parts[2] != "v=19" {
			return false, nil
		}
		salt, err := base64.RawStdEncoding.DecodeString(parts[4])
		if err != nil {
			return false, nil
		}
		expected, err := base64.RawStdEncoding.DecodeString(parts[5])
		if err != nil {
			return false, nil
		}
		params := strings.Split(parts[3], ",")
		if len(params) != 3 {
			return false, nil
		}
		values := make([]uint64, 3)
		for i, label := range []string{"m=", "t=", "p="} {
			if !strings.HasPrefix(params[i], label) {
				return false, nil
			}
			n, err := strconv.ParseUint(strings.TrimPrefix(params[i], label), 10, 32)
			if err != nil {
				return false, nil
			}
			values[i] = n
		}
		memory, iterations, threads := values[0], values[1], values[2]
		// Read self-described Python/Go hashes, with resource bounds for damaged input.
		if threads < 1 || threads > 8 || memory < 8*threads || memory > 256*1024 || iterations < 1 || iterations > 10 || len(salt) < 8 || len(salt) > 64 || len(expected) < 16 || len(expected) > 64 {
			return false, nil
		}
		hash := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(threads), uint32(len(expected)))
		return subtle.ConstantTimeCompare(hash, expected) == 1, nil
	}
	// 旧版兼容：username 作为盐（仅用于迁移期，新注册一律使用随机盐）
	legacyHash := argon2.IDKey([]byte(password), []byte(legacyUsername), 1, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(legacyHash, []byte(encoded)) == 1, nil
}

// RegisterUser 将新用户插入数据库，密码经过Argon2哈希
func RegisterUser(username, password string) error {
	// 输入校验：限制长度，防止超大字段撑爆数据库
	if utf8.RuneCountInString(username) < 2 || utf8.RuneCountInString(username) > 20 {
		return errors.New("用户名长度必须在 2-20 个字符之间")
	}
	if utf8.RuneCountInString(password) < 6 || utf8.RuneCountInString(password) > 64 {
		return errors.New("密码长度必须在 6-64 个字符之间")
	}

	// 先检查用户名是否已存在，避免依赖 SQLite 方言的错误字符串
	exists, err := UserExists(username)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("用户名已存在")
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		return err
	}

	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	token, err := storage.putName(tx, username)
	if err != nil {
		return err
	}
	encoded, err := storage.seal(hashedPassword, "users", "password", token)
	if err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO users(username,password) VALUES(?,?)", token, encoded); err != nil {
		return err
	}
	return tx.Commit()
}

// ValidateUser 验证用户名和密码
func ValidateUser(username, password string) (bool, error) {
	var storedPassword string
	err := DB.QueryRow("SELECT password FROM users WHERE username = ?", storage.token(username)).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil // 用户不存在
		}
		return false, err
	}

	storedPassword, err = storage.open(storedPassword, "users", "password", storage.token(username))
	if err != nil {
		return false, err
	}
	return verifyPassword(password, storedPassword, username)
}

// UserExists 检查用户是否存在
func UserExists(username string) (bool, error) {
	var id int
	err := DB.QueryRow("SELECT id FROM users WHERE username = ?", storage.token(username)).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
