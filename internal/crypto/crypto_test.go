package crypto_test

import (
	"strings"
	"testing"

	"github.com/local/password-vault/internal/crypto"
)

var testMasterKey = []byte("12345678901234567890123456789012") // 32 bytes

func TestKeyHash_Deterministic(t *testing.T) {
	h1 := crypto.KeyHash(testMasterKey, "my_secret")
	h2 := crypto.KeyHash(testMasterKey, "my_secret")
	if h1 != h2 {
		t.Fatal("KeyHash should be deterministic")
	}
}

func TestKeyHash_DifferentKeys(t *testing.T) {
	h1 := crypto.KeyHash(testMasterKey, "key_a")
	h2 := crypto.KeyHash(testMasterKey, "key_b")
	if h1 == h2 {
		t.Fatal("different key names must produce different hashes")
	}
}

func TestKeyHash_DifferentMasterKeys(t *testing.T) {
	key2 := []byte("aaaabbbbccccddddeeeeffffgggghhhh")
	h1 := crypto.KeyHash(testMasterKey, "same_name")
	h2 := crypto.KeyHash(key2, "same_name")
	if h1 == h2 {
		t.Fatal("different master keys must produce different hashes")
	}
}

func TestDeriveEncKey_Deterministic(t *testing.T) {
	k1, err := crypto.DeriveEncKey(testMasterKey, "my_secret")
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := crypto.DeriveEncKey(testMasterKey, "my_secret")
	if string(k1) != string(k2) {
		t.Fatal("DeriveEncKey must be deterministic")
	}
	if len(k1) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(k1))
	}
}

func TestDeriveEncKey_UniquePerKeyName(t *testing.T) {
	k1, _ := crypto.DeriveEncKey(testMasterKey, "name_a")
	k2, _ := crypto.DeriveEncKey(testMasterKey, "name_b")
	if string(k1) == string(k2) {
		t.Fatal("different key names must yield different enc keys")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key, _ := crypto.DeriveEncKey(testMasterKey, "roundtrip")
	plaintext := "super secret value 🔐"

	enc, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if enc == plaintext {
		t.Fatal("ciphertext must differ from plaintext")
	}

	dec, err := crypto.Decrypt(key, enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec != plaintext {
		t.Fatalf("want %q, got %q", plaintext, dec)
	}
}

func TestEncrypt_UniqueNonces(t *testing.T) {
	key, _ := crypto.DeriveEncKey(testMasterKey, "nonce_test")
	enc1, _ := crypto.Encrypt(key, "same value")
	enc2, _ := crypto.Encrypt(key, "same value")
	if enc1 == enc2 {
		t.Fatal("each Encrypt call must produce a unique ciphertext (different nonce)")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1, _ := crypto.DeriveEncKey(testMasterKey, "key1")
	key2, _ := crypto.DeriveEncKey(testMasterKey, "key2")

	enc, _ := crypto.Encrypt(key1, "secret")
	_, err := crypto.Decrypt(key2, enc)
	if err == nil {
		t.Fatal("decrypting with wrong key must fail")
	}
}

func TestDecrypt_Tampered(t *testing.T) {
	key, _ := crypto.DeriveEncKey(testMasterKey, "tamper_test")
	enc, _ := crypto.Encrypt(key, "value")

	// Flip last byte of the base64 string to simulate tampering
	b := []byte(enc)
	b[len(b)-1] ^= 1
	_, err := crypto.Decrypt(key, string(b))
	if err == nil {
		t.Fatal("tampered ciphertext must fail authentication")
	}
}

func TestHashToken_VerifyToken(t *testing.T) {
	rawToken, _, err := crypto.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}

	hash, err := crypto.HashToken(rawToken)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hash, "$") {
		t.Fatal("hash must contain salt$hash separator")
	}

	if !crypto.VerifyToken(rawToken, hash) {
		t.Fatal("VerifyToken should return true for correct token")
	}
}

func TestVerifyToken_WrongToken(t *testing.T) {
	rawToken, _, _ := crypto.GenerateToken()
	hash, _ := crypto.HashToken(rawToken)

	wrongToken, _, _ := crypto.GenerateToken()
	if crypto.VerifyToken(wrongToken, hash) {
		t.Fatal("VerifyToken should return false for wrong token")
	}
}

func TestHashToken_UniqueHashes(t *testing.T) {
	rawToken, _, _ := crypto.GenerateToken()
	h1, _ := crypto.HashToken(rawToken)
	h2, _ := crypto.HashToken(rawToken)
	// Different salts → different hashes for same input
	if h1 == h2 {
		t.Fatal("HashToken should produce unique hashes due to random salts")
	}
}

func TestTokenSHA256_Deterministic(t *testing.T) {
	rawToken, _, _ := crypto.GenerateToken()
	h1 := crypto.TokenSHA256(rawToken)
	h2 := crypto.TokenSHA256(rawToken)
	if h1 != h2 {
		t.Fatal("TokenSHA256 must be deterministic")
	}
}

func TestGenerateToken_Length(t *testing.T) {
	raw, encoded, err := crypto.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Fatalf("raw token must be 32 bytes, got %d", len(raw))
	}
	if len(encoded) == 0 {
		t.Fatal("encoded token must not be empty")
	}
}

func TestGenerateMasterKey(t *testing.T) {
	k1, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := crypto.GenerateMasterKey()
	if k1 == k2 {
		t.Fatal("master keys must be unique")
	}
	if len(k1) < 40 {
		t.Fatal("encoded master key suspiciously short")
	}
}
