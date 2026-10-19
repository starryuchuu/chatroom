package crypto

import (
	"bytes"
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
