package database

import (
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashAndVerify(t *testing.T) {
	h, err := hashPassword("secret123")
	if err != nil {
		t.Fatalf("hashPassword error: %v", err)
	}
	ok, err := verifyPassword("secret123", h, "")
	if err != nil || !ok {
		t.Fatalf("正确密码验证失败: ok=%v err=%v", ok, err)
	}
	ok, _ = verifyPassword("wrongpass", h, "")
	if ok {
		t.Fatal("错误密码不应通过验证")
	}
}

func TestLegacyHashCompat(t *testing.T) {
	// 旧格式：username 作盐的裸哈希
	legacy := string(argon2.IDKey([]byte("pass123"), []byte("user"), 1, 64*1024, 4, 32))
	ok, err := verifyPassword("pass123", legacy, "user")
	if err != nil || !ok {
		t.Fatalf("旧格式验证失败: ok=%v err=%v", ok, err)
	}
	ok, _ = verifyPassword("wrong", legacy, "user")
	if ok {
		t.Fatal("旧格式错误密码不应通过验证")
	}
}

func TestInvalidHashRejected(t *testing.T) {
	ok, err := verifyPassword("x", "$argon2id$broken$hash", "user")
	if err != nil {
		t.Fatalf("解析无效哈希不应报错（视为验证失败）: %v", err)
	}
	if ok {
		t.Fatal("无效哈希不应通过验证")
	}
}
