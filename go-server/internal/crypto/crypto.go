package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"

	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

var privateKey *rsa.PrivateKey
var publicKeyBytes []byte

// EnsureRSAKeys 检查RSA密钥文件是否存在，如果不存在则生成
func EnsureRSAKeys() (*rsa.PrivateKey, []byte) {
	privateKeyFile := "private_key.pem"
	publicKeyFile := "public_key.pem"

	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		log.Println("未找到RSA密钥，正在生成新的密钥对...")
		generateRSAKeys(privateKeyFile, publicKeyFile)
	}

	// 加载私钥
	privKeyBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		log.Fatalf("无法读取私钥文件: %v", err)
	}
	privPem, _ := pem.Decode(privKeyBytes)
	if privPem == nil || privPem.Type != "RSA PRIVATE KEY" {
		log.Fatal("私钥文件格式无效")
	}
	privateKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		log.Fatalf("无法解析私钥: %v", err)
	}

	// 加载公钥
	publicKeyBytes, err = os.ReadFile(publicKeyFile)
	if err != nil {
		log.Fatalf("无法读取公钥文件: %v", err)
	}
	pubPem, _ := pem.Decode(publicKeyBytes)
	if pubPem == nil || pubPem.Type != "PUBLIC KEY" {
		log.Fatal("公钥文件格式无效")
	}

	log.Println("RSA密钥已成功加载。")
	return privateKey, publicKeyBytes
}

// generateRSAKeys 生成并保存RSA密钥对
func generateRSAKeys(privPath, pubPath string) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("无法生成RSA密钥: %v", err)
	}

	// 保存私钥 (PKCS#1)
	privKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
	privFile, err := os.Create(privPath)
	if err != nil {
		log.Fatalf("无法创建私钥文件: %v", err)
	}
	defer privFile.Close()
	if err := pem.Encode(privFile, privKeyPEM); err != nil {
		log.Fatalf("无法编码私钥到文件: %v", err)
	}

	// 保存公钥 (PKIX)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		log.Fatalf("无法序列化公钥: %v", err)
	}
	pubKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	pubFile, err := os.Create(pubPath)
	if err != nil {
		log.Fatalf("无法创建公钥文件: %v", err)
	}
	defer pubFile.Close()
	if err := pem.Encode(pubFile, pubKeyPEM); err != nil {
		log.Fatalf("无法编码公钥到文件: %v", err)
	}
}

// EncryptMessage 使用AES-GCM加密消息
func EncryptMessage(plainText string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// PyCryptodome 使用 16 字节的 nonce, Go 标准库通常是 12 字节
	// 我们需要创建一个 16 字节的 nonce
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return "", err
	}

	cipherText := aesgcm.Seal(nil, nonce, []byte(plainText), nil)

	// 组合 nonce + ciphertext + tag (tag 已包含在 Seal 的结果中)
	// Seal 的结果是 ciphertext + tag
	encryptedData := append(nonce, cipherText...)

	return base64.StdEncoding.EncodeToString(encryptedData), nil
}

// DecryptMessage 使用AES-GCM解密消息
func DecryptMessage(encryptedMessage string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return "", err
	}

	if len(data) < 16+16 { // 至少需要 nonce(16) + tag(16)
		return "", errors.New("加密数据太短")
	}

	nonce := data[:16]
	cipherTextWithTag := data[16:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return "", err
	}

	plainText, err := aesgcm.Open(nil, nonce, cipherTextWithTag, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

// ImportPublicKey 从PEM格式的字节数据中导入RSA公钥
func ImportPublicKey(publicKeyPEM []byte) (*rsa.PublicKey, error) {
	pubPem, _ := pem.Decode(publicKeyPEM)
	if pubPem == nil || pubPem.Type != "PUBLIC KEY" {
		return nil, errors.New("公钥文件格式无效")
	}

	publicKey, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("解析的公钥不是RSA公钥")
	}

	return rsaPublicKey, nil
}
