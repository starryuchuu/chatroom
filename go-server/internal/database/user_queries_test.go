package database

import (
	"path/filepath"
	"testing"
)

func TestRegistrationCountsCharactersInsteadOfUTF8Bytes(t *testing.T) {
	InitDB(filepath.Join(t.TempDir(), "chat.db"))
	defer DB.Close()
	if err := RegisterUser("中文用户名测试一二三四", "中文密码六个"); err != nil {
		t.Fatalf("valid Unicode credentials rejected: %v", err)
	}
	if err := RegisterUser("中", "password123"); err == nil {
		t.Fatal("one-character username accepted because its UTF-8 encoding has three bytes")
	}
}
