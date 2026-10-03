package password

import (
	"crypto/sha256"
	"encoding/base64"
	"golang.org/x/crypto/argon2"
	"strings"
	"testing"
)

func TestDummyUsesSameBoundedKDFAsRealCredential(t *testing.T) {
	raw := "$argon2id$v=19$m=65536,t=3,p=4$" + base64.RawStdEncoding.EncodeToString([]byte("test-salt-16byte")) + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	real, err := Parse([]byte(raw), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		credential Credential
		wantMatch  bool
	}{
		{"real", real, true},
		{"dummy", Dummy(true), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := tc.credential.verify([]byte("submitted-password"), func(provided, salt []byte, iterations, memory uint32, parallelism uint8, keyLen uint32) []byte {
				calls++
				if string(provided) != "submitted-password" || len(salt) < 8 || len(salt) > 64 {
					t.Error("invalid KDF password or salt")
				}
				if iterations != 3 || memory != 65536 || parallelism != 4 || keyLen != 32 {
					t.Errorf("KDF cost = t:%d m:%d p:%d len:%d", iterations, memory, parallelism, keyLen)
				}
				// Match the synthetic digest: even a matching dummy must reject.
				return make([]byte, 32)
			})
			if calls != 1 {
				t.Errorf("KDF calls = %d; want exactly 1", calls)
			}
			if (err == nil) != tc.wantMatch {
				t.Errorf("verification match = %t; want %t", err == nil, tc.wantMatch)
			}
		})
	}
}

func TestPlainDummyRejectsEvenMatchingDigest(t *testing.T) {
	dummy := Dummy(false)
	dummy.plain = sha256.Sum256([]byte("matching"))
	if err := dummy.Verify([]byte("matching")); err == nil {
		t.Fatal("dummy credential must never authenticate")
	}
}

func TestDummyArgon2Verification(t *testing.T) {
	if err := Dummy(true).Verify([]byte("submitted-password")); err == nil {
		t.Fatal("dummy credential must reject after real Argon2 derivation")
	}
}

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
