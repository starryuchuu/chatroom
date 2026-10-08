package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"
)

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
