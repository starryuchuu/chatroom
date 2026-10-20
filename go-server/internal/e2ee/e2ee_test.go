package e2ee

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"filippo.io/edwards25519"
)

func testIdentity(seed byte) (map[string]interface{}, ed25519.PrivateKey) {
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat(string([]byte{seed}), 32)))
	return map[string]interface{}{"v": 1, "sign": base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)),
		"exchange": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))}, private
}

func TestCanonicalMatchesPythonUnicodeAndEscaping(t *testing.T) {
	value := map[string]interface{}{"名😀": "<>/&\"\\\b\f\n\r\t\x00\x1f\x7f\u2028\u2029é😀", "v": float64(1)}
	actual, err := Canonical(value)
	expected := `{"v":1,"\u540d\ud83d\ude00":"<>/&\"\\\b\f\n\r\t\u0000\u001f\u007f\u2028\u2029\u00e9\ud83d\ude00"}`
	if err != nil || string(actual) != expected {
		t.Fatalf("canonical mismatch: %s %v expected %s", actual, err, expected)
	}
}

func TestIdentityProofBindsAccountAndImmutablePublicMaterial(t *testing.T) {
	bundle, private := testIdentity(1)
	sign, _ := decode(bundle["sign"], 32)
	exchange, _ := decode(bundle["exchange"], 32)
	message := append([]byte("chatroom-e2ee-key-v1\x00用户\x00"), sign...)
	message = append(message, exchange...)
	proof := base64.StdEncoding.EncodeToString(ed25519.Sign(private, message))
	if err := VerifyPublication("用户", bundle, proof); err != nil {
		t.Fatal(err)
	}
	if VerifyPublication("attacker", bundle, proof) == nil {
		t.Fatal("publication proof was replayed across accounts")
	}
	bundle["exchange"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if VerifyPublication("用户", bundle, proof) == nil {
		t.Fatal("publication accepted a substituted exchange key")
	}
}

func signedEnvelope(t *testing.T) (map[string]interface{}, map[string]map[string]interface{}) {
	t.Helper()
	alice, private := testIdentity(1)
	bob, _ := testIdentity(2)
	aliceID, _ := Fingerprint(alice)
	bobID, _ := Fingerprint(bob)
	envelope := map[string]interface{}{"v": 1, "id": strings.Repeat("a", 32), "kind": "private", "sender": "用户😀", "target": "bob",
		"sender_key": alice, "recipients": map[string]interface{}{"用户😀": aliceID, "bob": bobID},
		"ephemeral": alice["exchange"], "nonce": base64.StdEncoding.EncodeToString(make([]byte, 12)),
		"body": base64.StdEncoding.EncodeToString(make([]byte, 32)), "keys": map[string]interface{}{
			"用户😀": base64.StdEncoding.EncodeToString(make([]byte, 60)), "bob": base64.StdEncoding.EncodeToString(make([]byte, 60))}}
	data, err := Canonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte("chatroom-e2ee-envelope-v1\x00"), data...)))
	return envelope, map[string]map[string]interface{}{"用户😀": alice, "bob": bob}
}

func TestEnvelopeAuthenticatesBodyRecipientsAndRouting(t *testing.T) {
	envelope, identities := signedEnvelope(t)
	if _, err := ValidateEnvelope(envelope, "用户😀", "private", "bob", identities); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]interface{}){
		func(value map[string]interface{}) { value["target"] = "carol" },
		func(value map[string]interface{}) {
			value["body"] = base64.StdEncoding.EncodeToString(make([]byte, 40))
		},
		func(value map[string]interface{}) {
			value["recipients"].(map[string]interface{})["bob"] = strings.Repeat("0", 64)
		},
		func(value map[string]interface{}) {
			value["keys"].(map[string]interface{})["bob"] = base64.StdEncoding.EncodeToString(make([]byte, 59))
		},
		func(value map[string]interface{}) { value["nonce"] = "not-base64" },
		func(value map[string]interface{}) { value["id"] = strings.Repeat("A", 32) },
		func(value map[string]interface{}) { value["v"] = true },
		func(value map[string]interface{}) { value["unsigned"] = "injected" },
	} {
		serialized, _ := json.Marshal(envelope)
		var copy map[string]interface{}
		json.Unmarshal(serialized, &copy)
		mutate(copy)
		if _, err := ValidateEnvelope(copy, "用户😀", "private", "bob", identities); err == nil {
			t.Fatalf("tampered envelope accepted: %v", copy)
		}
	}
	delete(identities, "bob")
	if _, err := ValidateEnvelope(envelope, "用户😀", "private", "bob", identities); err == nil {
		t.Fatal("stale group/recipient membership accepted")
	}
}

func TestPythonSignedUnicodeEnvelopeAndPublicProofs(t *testing.T) {
	raw, err := os.ReadFile("testdata/python-envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]interface{}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	alice, bob := vector["alice_username"].(string), vector["bob_username"].(string)
	aliceBundle, bobBundle := vector["alice_bundle"].(map[string]interface{}), vector["bob_bundle"].(map[string]interface{})
	if err := VerifyPublication(alice, aliceBundle, vector["alice_proof"]); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublication(bob, bobBundle, vector["bob_proof"]); err != nil {
		t.Fatal(err)
	}
	envelope := vector["envelope"].(map[string]interface{})
	if _, err := ValidateEnvelope(envelope, alice, "group", envelope["target"].(string), map[string]map[string]interface{}{alice: aliceBundle, bob: bobBundle}); err != nil {
		t.Fatalf("Python Unicode signature did not verify: %v", err)
	}
}

func TestRejectsWeakNoncanonicalAndMixedOrderPublicKeys(t *testing.T) {
	bundle, _ := testIdentity(7)
	signRaw, _ := base64.StdEncoding.DecodeString(bundle["sign"].(string))
	point, _ := new(edwards25519.Point).SetBytes(signRaw)
	torsionBytes := []byte(strings.Repeat("\xff", 32))
	torsionBytes[0], torsionBytes[31] = 0xec, 0x7f // y=-1, order two.
	torsion, err := new(edwards25519.Point).SetBytes(torsionBytes)
	if err != nil {
		t.Fatal(err)
	}
	mixed := new(edwards25519.Point).Add(point, torsion).Bytes()
	identity := make([]byte, 32)
	identity[0] = 1
	for _, raw := range [][]byte{make([]byte, 32), identity, torsionBytes, mixed} {
		copy := map[string]interface{}{"v": 1, "sign": base64.StdEncoding.EncodeToString(raw), "exchange": bundle["exchange"]}
		if _, err := Bundle(copy); err == nil {
			t.Fatalf("weak signing point accepted: %x", raw)
		}
	}
	prime := []byte(strings.Repeat("\xff", 32))
	prime[0], prime[31] = 0xed, 0x7f
	alias := append([]byte(nil), prime...)
	alias[0]++
	highBit, _ := base64.StdEncoding.DecodeString(bundle["exchange"].(string))
	highBit[31] |= 0x80
	one := make([]byte, 32)
	one[0] = 1
	for _, raw := range [][]byte{make([]byte, 32), one, prime, alias, highBit} {
		copy := map[string]interface{}{"v": 1, "sign": bundle["sign"], "exchange": base64.StdEncoding.EncodeToString(raw)}
		if _, err := Bundle(copy); err == nil {
			t.Fatalf("weak/aliased exchange point accepted: %x", raw)
		}
	}
}
