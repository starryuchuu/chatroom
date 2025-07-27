package database

import (
	"database/sql"
	"errors"

	"golang.org/x/crypto/argon2"
)

// RegisterUser 将新用户插入数据库，密码经过Argon2哈希
func RegisterUser(username, password string) error {
	// 使用Argon2的默认参数，这通常与大多数库兼容
	hashedPassword := argon2.IDKey([]byte(password), []byte(username), 1, 64*1024, 4, 32)

	stmt, err := DB.Prepare("INSERT INTO users (username, password) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(username, hashedPassword)
	if err != nil {
		// 检查是否是唯一性约束冲突
		if err.Error() == "UNIQUE constraint failed: users.username" {
			return errors.New("用户名已存在")
		}
		return err
	}
	return nil
}

// ValidateUser 验证用户名和密码
func ValidateUser(username, password string) (bool, error) {
	var storedPassword []byte
	err := DB.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil // 用户不存在
		}
		return false, err
	}

	// 使用相同的参数进行哈希以进行比较
	hashedPassword := argon2.IDKey([]byte(password), []byte(username), 1, 64*1024, 4, 32)

	// 比较哈希值
	if string(storedPassword) == string(hashedPassword) {
		return true, nil
	}

	return false, nil
}

// UserExists 检查用户是否存在
func UserExists(username string) (bool, error) {
	var id int
	err := DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
