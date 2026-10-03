package password

import (
	"encoding/base64"
	"golang.org/x/crypto/argon2"
	"strings"
	"testing"
)

func TestStrictPHC(t *testing.T) {
	salt := []byte("test-salt-16byte")
	hash := argon2.IDKey([]byte("correct"), salt, 3, 65536, 4, 32)
	good := "$argon2id$v=19$m=65536,t=3,p=4$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	c, err := Parse([]byte(good), true)
	if err != nil || c.Verify([]byte("correct")) != nil || c.Verify([]byte("wrong")) == nil {
		t.Fatal("verification", err)
	}
	for _, raw := range []string{"plaintext", good + "$extra", strings.Replace(good, "m=65536,t=3,p=4", "m=65536,t=3,p=4,m=65536", 1), strings.Replace(good, base64.RawStdEncoding.EncodeToString(salt), "", 1), strings.Replace(good, base64.RawStdEncoding.EncodeToString(hash), "YQ", 1), strings.Replace(good, "argon2id", "argon2i", 1)} {
		if _, err := Parse([]byte(raw), true); err == nil {
			t.Fatalf("accepted malformed %q", raw)
		}
	}
}
func TestPlaintextCredentialDetached(t *testing.T) {
	raw := []byte("correct\n")
	c, err := Parse(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 'x'
	if c.Verify([]byte("correct")) != nil {
		t.Fatal("aliases caller")
	}
}
