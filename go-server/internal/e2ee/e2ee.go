// Package e2ee validates signed client ciphertext without possessing client keys.
package e2ee

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf8"

	"filippo.io/edwards25519"
)

const MaxRecipients = 256
const MaxPlaintextBytes = 256 * 1024

var messageID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Canonical matches Python json.dumps(sort_keys=True, ensure_ascii=True,
// separators=(',', ':'), allow_nan=False). E2EE documents contain no floats
// other than the JSON-decoded integer version field.
func Canonical(value interface{}) ([]byte, error) {
	var output bytes.Buffer
	if err := appendCanonical(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func appendString(output *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return errors.New("invalid UTF-8")
	}
	output.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteRune(character)
		case '\b':
			output.WriteString(`\b`)
		case '\f':
			output.WriteString(`\f`)
		case '\n':
			output.WriteString(`\n`)
		case '\r':
			output.WriteString(`\r`)
		case '\t':
			output.WriteString(`\t`)
		default:
			if character < 0x20 || character >= 0x7f {
				if character > 0xffff {
					character -= 0x10000
					fmt.Fprintf(output, `\u%04x\u%04x`, 0xd800+(character>>10), 0xdc00+(character&0x3ff))
				} else {
					fmt.Fprintf(output, `\u%04x`, character)
				}
			} else {
				output.WriteRune(character)
			}
		}
	}
	output.WriteByte('"')
	return nil
}

func appendCanonical(output *bytes.Buffer, value interface{}) error {
	switch item := value.(type) {
	case string:
		return appendString(output, item)
	case map[string]interface{}:
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index != 0 {
				output.WriteByte(',')
			}
			if err := appendString(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := appendCanonical(output, item[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	case map[string]string:
		converted := make(map[string]interface{}, len(item))
		for key, value := range item {
			converted[key] = value
		}
		return appendCanonical(output, converted)
	case []interface{}:
		output.WriteByte('[')
		for index, value := range item {
			if index != 0 {
				output.WriteByte(',')
			}
			if err := appendCanonical(output, value); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case int:
		output.WriteString(strconv.Itoa(item))
	case float64:
		if math.IsNaN(item) || math.IsInf(item, 0) || math.Trunc(item) != item || math.Abs(item) > 9007199254740991 {
			return errors.New("non-integer JSON number")
		}
		output.WriteString(strconv.FormatFloat(item, 'f', 0, 64))
	case bool:
		output.WriteString(strconv.FormatBool(item))
	case nil:
		output.WriteString("null")
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}

func exactFields(value map[string]interface{}, fields ...string) bool {
	if len(value) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, present := value[field]; !present {
			return false
		}
	}
	return true
}

func versionOne(value interface{}) bool {
	switch number := value.(type) {
	case int:
		return number == 1
	case float64:
		return number == 1
	default:
		return false
	}
}

func decode(value interface{}, length int) ([]byte, error) {
	encoded, valid := value.(string)
	if !valid || len(encoded) != base64.StdEncoding.EncodedLen(length) {
		return nil, errors.New("invalid E2EE binary field")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) != length || base64.StdEncoding.EncodeToString(data) != encoded {
		return nil, errors.New("invalid E2EE binary field")
	}
	return data, nil
}

func validSigningKey(raw []byte) bool {
	point, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil || !bytes.Equal(point.Bytes(), raw) {
		return false
	}
	// Removing the cofactor then multiplying by 8^-1 projects onto the prime
	// subgroup. Equality rejects mixed-order points as well as small-order keys.
	cofactor := new(edwards25519.Point).MultByCofactor(point)
	identity := edwards25519.NewIdentityPoint()
	if cofactor.Equal(identity) == 1 {
		return false
	}
	eightBytes := make([]byte, 32)
	eightBytes[0] = 8
	eight, _ := new(edwards25519.Scalar).SetCanonicalBytes(eightBytes)
	inverse := new(edwards25519.Scalar).Invert(eight)
	return new(edwards25519.Point).ScalarMult(inverse, cofactor).Equal(point) == 1
}

func validExchangeKey(raw []byte) bool {
	if len(raw) != 32 || raw[31]&0x80 != 0 {
		return false
	}
	// RFC 7748 decoding permits aliases; the E2EE identity format requires the
	// unique field representative below 2^255-19 before fingerprinting it.
	prime := bytes.Repeat([]byte{0xff}, 32)
	prime[0], prime[31] = 0xed, 0x7f
	canonical := false
	for index := 31; index >= 0; index-- {
		if raw[index] < prime[index] {
			canonical = true
			break
		}
		if raw[index] > prime[index] {
			return false
		}
	}
	if !canonical {
		return false
	}
	public, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return false
	}
	validation, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	_, err = validation.ECDH(public)
	return err == nil
}

// Bundle validates and normalizes public identity material only.
func Bundle(value interface{}) (map[string]interface{}, error) {
	bundle, valid := value.(map[string]interface{})
	if !valid || !exactFields(bundle, "v", "sign", "exchange") || !versionOne(bundle["v"]) {
		return nil, errors.New("invalid E2EE public identity")
	}
	sign, err := decode(bundle["sign"], 32)
	if err != nil || !validSigningKey(sign) {
		return nil, errors.New("invalid E2EE signing public key")
	}
	exchange, err := decode(bundle["exchange"], 32)
	if err != nil || !validExchangeKey(exchange) {
		return nil, errors.New("invalid E2EE exchange public key")
	}
	return bundle, nil
}

func Fingerprint(bundle map[string]interface{}) (string, error) {
	if _, err := Bundle(bundle); err != nil {
		return "", err
	}
	data, err := Canonical(bundle)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func VerifyPublication(username string, bundle map[string]interface{}, proof interface{}) error {
	if _, err := Bundle(bundle); err != nil {
		return err
	}
	sign, _ := decode(bundle["sign"], 32)
	exchange, _ := decode(bundle["exchange"], 32)
	signature, err := decode(proof, 64)
	if err != nil {
		return err
	}
	message := append([]byte("chatroom-e2ee-key-v1\x00"+username+"\x00"), sign...)
	message = append(message, exchange...)
	if !ed25519.Verify(sign, message, signature) {
		return errors.New("invalid E2EE publication proof")
	}
	return nil
}

// ValidateEnvelope checks its complete signed routing context and current
// authorized recipient identities. It never decrypts the body or wrapped keys.
func ValidateEnvelope(value interface{}, sender, kind, target string, identities map[string]map[string]interface{}) (map[string]interface{}, error) {
	envelope, valid := value.(map[string]interface{})
	if !valid || !exactFields(envelope, "v", "id", "kind", "sender", "target", "sender_key", "recipients", "ephemeral", "nonce", "body", "keys", "signature") || !versionOne(envelope["v"]) {
		return nil, errors.New("invalid E2EE envelope")
	}
	id, valid := envelope["id"].(string)
	if !valid || !messageID.MatchString(id) || envelope["sender"] != sender || envelope["kind"] != kind || envelope["target"] != target {
		return nil, errors.New("E2EE routing context mismatch")
	}
	if len(identities) == 0 || len(identities) > MaxRecipients {
		return nil, errors.New("invalid E2EE recipient count")
	}
	senderKey, err := Bundle(envelope["sender_key"])
	if err != nil {
		return nil, err
	}
	registeredSender := identities[sender]
	if registeredSender == nil {
		return nil, errors.New("E2EE sender has no public identity")
	}
	senderFingerprint, _ := Fingerprint(senderKey)
	registeredFingerprint, err := Fingerprint(registeredSender)
	if err != nil || senderFingerprint != registeredFingerprint {
		return nil, errors.New("E2EE sender identity mismatch")
	}
	recipients, validRecipients := envelope["recipients"].(map[string]interface{})
	keys, validKeys := envelope["keys"].(map[string]interface{})
	if !validRecipients || !validKeys || len(recipients) != len(identities) || len(keys) != len(identities) {
		return nil, errors.New("E2EE recipient list changed; refresh keys")
	}
	for username, identity := range identities {
		fingerprint, err := Fingerprint(identity)
		if err != nil || recipients[username] != fingerprint {
			return nil, errors.New("E2EE recipient identity changed; refresh keys")
		}
		if _, err := decode(keys[username], 60); err != nil {
			return nil, err
		}
	}
	for _, field := range []struct {
		name   string
		length int
	}{{"ephemeral", 32}, {"nonce", 12}, {"signature", 64}} {
		if _, err := decode(envelope[field.name], field.length); err != nil {
			return nil, err
		}
	}
	ephemeral, _ := decode(envelope["ephemeral"], 32)
	if !validExchangeKey(ephemeral) {
		return nil, errors.New("invalid E2EE ephemeral public key")
	}
	body, validBody := envelope["body"].(string)
	if !validBody || len(body) > base64.StdEncoding.EncodedLen(MaxPlaintextBytes+16) {
		return nil, errors.New("E2EE message body too large")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(body)
	if err != nil || len(data) < 16 || len(data) > MaxPlaintextBytes+16 || base64.StdEncoding.EncodeToString(data) != body {
		return nil, errors.New("invalid E2EE message body")
	}
	unsigned := make(map[string]interface{}, len(envelope)-1)
	for name, value := range envelope {
		if name != "signature" {
			unsigned[name] = value
		}
	}
	canonical, err := Canonical(unsigned)
	if err != nil {
		return nil, err
	}
	sign, _ := decode(senderKey["sign"], 32)
	signature, _ := decode(envelope["signature"], 64)
	if !ed25519.Verify(sign, append([]byte("chatroom-e2ee-envelope-v1\x00"), canonical...), signature) {
		return nil, errors.New("invalid E2EE envelope signature")
	}
	return envelope, nil
}

// ParseBundle handles encrypted public-directory storage, which only stores a
// canonical public bundle. Missing or corrupt data is never treated as legacy.
func ParseBundle(serialized string) (map[string]interface{}, error) {
	var bundle map[string]interface{}
	if err := json.Unmarshal([]byte(serialized), &bundle); err != nil {
		return nil, err
	}
	return Bundle(bundle)
}
