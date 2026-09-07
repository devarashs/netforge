package cryptotool

import (
	"encoding/hex"
	"testing"
)

// TestPBKDF2KnownAnswers checks the from-scratch PBKDF2-HMAC-SHA256 against
// published test vectors (draft-josefsson-pbkdf2-test-vectors).
func TestPBKDF2KnownAnswers(t *testing.T) {
	cases := []struct {
		pass, salt string
		iter       int
		want       string
	}{
		{"password", "salt", 1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"password", "salt", 2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(pbkdf2SHA256([]byte(c.pass), []byte(c.salt), c.iter, 32))
		if got != c.want {
			t.Errorf("pbkdf2(%q,%q,%d)=%s want %s", c.pass, c.salt, c.iter, got, c.want)
		}
	}
}

// TestAESRoundTrip verifies GCM encrypt/decrypt and that a wrong key fails.
func TestAESRoundTrip(t *testing.T) {
	key := pbkdf2SHA256([]byte("passphrase"), []byte("0123456789abcdef"), 1000, keyLen)
	gcm, err := newGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, nonceLen)
	msg := []byte("the quick brown fox")
	ct := gcm.Seal(nil, nonce, msg, nil)

	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(pt) != string(msg) {
		t.Fatalf("roundtrip mismatch: %q", pt)
	}

	badKey := pbkdf2SHA256([]byte("wrong"), []byte("0123456789abcdef"), 1000, keyLen)
	badGCM, _ := newGCM(badKey)
	if _, err := badGCM.Open(nil, nonce, ct, nil); err == nil {
		t.Fatal("expected authentication failure with wrong key")
	}
}
