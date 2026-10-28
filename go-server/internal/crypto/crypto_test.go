package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"testing"
)

func TestMissingPrivateKeyPreservesIdentity(t *testing.T) {
	if os.Getenv("CHATROOM_RSA_MISSING_PRIVATE_HELPER") == "1" {
		EnsureRSAKeys()
		return
	}
	t.Chdir(t.TempDir())
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile("public_key.pem", public, 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestMissingPrivateKeyPreservesIdentity$")
	command.Env = append(os.Environ(), "CHATROOM_RSA_MISSING_PRIVATE_HELPER=1")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Errorf("startup silently replaced an existing identity: %s", output)
	} else if !bytes.Contains(output, []byte("恢复原私钥")) {
		t.Fatalf("startup failed for an unexpected reason: %s", output)
	}
	if _, err := os.Stat("private_key.pem"); !os.IsNotExist(err) {
		t.Error("missing private key was replaced instead of requiring recovery")
	}
	retained, err := os.ReadFile("public_key.pem")
	if err != nil || !bytes.Equal(retained, public) {
		t.Error("original public identity was overwritten")
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile("private_key.pem", private, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, recoveredPublic := EnsureRSAKeys()
	if loaded.N.Cmp(key.N) != 0 || !bytes.Equal(recoveredPublic, public) {
		t.Fatal("restoring the original private key did not recover the pinned identity")
	}
}

func TestExistingPrivateKeyPermissionsAreRestricted(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Windows does not expose POSIX owner/group permission bits")
	}
	t.Chdir(t.TempDir())
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile("private_key.pem", private, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod("private_key.pem", 0644); err != nil {
		t.Fatal(err)
	}
	loaded, _ := EnsureRSAKeys()
	if loaded.N.Cmp(key.N) != 0 {
		t.Fatal("permission repair changed private identity")
	}
	info, err := os.Stat("private_key.pem")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("existing private key permissions were not restricted: %v", err)
	}
}

func TestEnsureRepairsPublicKeyWithoutRotatingPrivateKey(t *testing.T) {
	t.Chdir(t.TempDir())
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile("private_key.pem", privatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"missing", "mismatched", "invalid"} {
		t.Run(kind, func(t *testing.T) {
			switch kind {
			case "missing":
				os.Remove("public_key.pem")
			case "mismatched":
				other, err := rsa.GenerateKey(rand.Reader, 1024)
				if err != nil {
					t.Fatal(err)
				}
				der, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
				os.WriteFile("public_key.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0644)
			case "invalid":
				os.WriteFile("public_key.pem", []byte("broken"), 0644)
			}
			loaded, public := EnsureRSAKeys()
			if loaded.N.Cmp(key.N) != 0 {
				t.Fatal("repair changed private identity")
			}
			block, _ := pem.Decode(public)
			if block == nil {
				t.Fatal("invalid public PEM")
			}
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.(*rsa.PublicKey).N.Cmp(key.N) != 0 {
				t.Fatal("mismatched public key retained")
			}
		})
	}
}

func TestAESRoundTripAndTamperDetection(t *testing.T) {
	for _, size := range []int{16, 24, 32} {
		key := make([]byte, size)
		encrypted, err := EncryptMessage("你好 Go", key)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := DecryptMessage(encrypted, key)
		if err != nil || plain != "你好 Go" {
			t.Fatalf("round trip: %q %v", plain, err)
		}
		data, _ := base64.StdEncoding.DecodeString(encrypted)
		data[len(data)-1] ^= 1
		if _, err := DecryptMessage(base64.StdEncoding.EncodeToString(data), key); err == nil {
			t.Fatal("tampered tag accepted")
		}
	}
}

func TestDecryptMessageRejectsInvalidUTF8(t *testing.T) {
	key := []byte("0123456789abcdef")
	for _, plaintext := range []string{"\xff\xfe\x80", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "truncated \xe4\xbd"} {
		encrypted, err := EncryptMessage(plaintext, key)
		if err != nil {
			t.Fatal(err)
		}
		if result, err := DecryptMessage(encrypted, key); err == nil || result != "" {
			t.Fatalf("invalid UTF-8 %x accepted: %q, %v", plaintext, result, err)
		}
	}
	for _, plaintext := range []string{"", "你好🙂", "replacement \ufffd", "null\x00byte"} {
		encrypted, err := EncryptMessage(plaintext, key)
		if err != nil {
			t.Fatal(err)
		}
		if result, err := DecryptMessage(encrypted, key); err != nil || result != plaintext {
			t.Fatalf("valid UTF-8 %q rejected: %q, %v", plaintext, result, err)
		}
	}
}

func TestPKCS8PrivateKeyPreservesIdentityAndEncoding(t *testing.T) {
	t.Chdir(t.TempDir())
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile("private_key.pem", private, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, public := EnsureRSAKeys()
	if !loaded.Equal(key) {
		t.Fatal("PKCS#8 loading changed private identity")
	}
	retained, err := os.ReadFile("private_key.pem")
	if err != nil || !bytes.Equal(retained, private) {
		t.Fatal("PKCS#8 private key was rewritten")
	}
	pub, err := ImportPublicKey(public)
	if err != nil || !pub.Equal(&key.PublicKey) {
		t.Fatalf("derived public identity differs: %v", err)
	}
}

func TestUnsupportedPrivateKeysFailWithoutReplacingIdentity(t *testing.T) {
	if os.Getenv("CHATROOM_RSA_INVALID_PRIVATE_HELPER") == "1" {
		EnsureRSAKeys()
		return
	}
	_, nonRSA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(nonRSA)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{
		"non-RSA":      {Type: "PRIVATE KEY", Bytes: der},
		"broken-PKCS8": {Type: "PRIVATE KEY", Bytes: []byte("broken")},
		"broken-PKCS1": {Type: "RSA PRIVATE KEY", Bytes: []byte("broken")},
		"encrypted":    {Type: "ENCRYPTED PRIVATE KEY", Bytes: der},
	} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			private := pem.EncodeToMemory(block)
			if err := os.WriteFile("private_key.pem", private, 0600); err != nil {
				t.Fatal(err)
			}
			public := []byte("preserve public identity")
			if err := os.WriteFile("public_key.pem", public, 0644); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestUnsupportedPrivateKeysFailWithoutReplacingIdentity$")
			command.Env = append(os.Environ(), "CHATROOM_RSA_INVALID_PRIVATE_HELPER=1")
			output, err := command.CombinedOutput()
			if err == nil || !bytes.Contains(output, []byte("私钥")) {
				t.Fatalf("unexpected startup result: %v, %s", err, output)
			}
			for path, expected := range map[string][]byte{"private_key.pem": private, "public_key.pem": public} {
				retained, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(retained, expected) {
					t.Fatalf("%s was replaced", path)
				}
			}
		})
	}
}
