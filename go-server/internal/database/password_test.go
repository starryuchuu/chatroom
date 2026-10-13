package database

import (
	"encoding/base64"
	"strings"
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

func TestSelfDescribedPythonParametersAndBounds(t *testing.T) {
	salt := []byte("test salt 1234567")
	expected := argon2.IDKey([]byte("secret123"), salt, 3, 64*1024, 4, 32)
	encoded := "$argon2id$v=19$m=65536,t=3,p=4$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(expected)
	ok, err := verifyPassword("secret123", encoded, "")
	if err != nil || !ok {
		t.Fatal("Python parameters rejected", err)
	}
	for _, bad := range []string{"m=65536,t=0,p=4", "m=65536,t=999999,p=4", "m=999999999,t=1,p=4", "m=65536,t=1,p=0", "m=0,t=1,p=4"} {
		candidate := strings.Replace(encoded, "m=65536,t=3,p=4", bad, 1)
		ok, err = verifyPassword("secret123", candidate, "")
		if err != nil || ok {
			t.Fatal("unsafe parameters accepted", bad)
		}
	}
}
