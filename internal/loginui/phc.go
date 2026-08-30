package loginui

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	phcID       = "argon2id"
	phcVersion  = 19
	phcMemory   = 65536
	phcTime     = 3
	phcParallel = 4
)

func verifyPassword(stored, provided []byte) error {
	s := strings.TrimSpace(string(stored))
	if strings.HasPrefix(s, "$") {
		return verifyPHC(s, provided)
	}
	return compareConstant(stored, provided)
}

func verifyPHC(phc string, password []byte) error {
	parts := strings.Split(phc, "$")
	if len(parts) < 6 {
		return fmt.Errorf("malformed PHC")
	}
	id := parts[1]
	if id != phcID {
		return fmt.Errorf("unknown PHC id %q (fail-closed)", id)
	}
	if !strings.HasPrefix(parts[2], "v=") {
		return fmt.Errorf("plaintext/unsalted hash rejected")
	}
	ver, _ := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if ver != phcVersion {
		return fmt.Errorf("unsupported argon2 version")
	}
	params := parts[3]
	var m, t, p uint32
	for _, kv := range strings.Split(params, ",") {
		k, v, _ := strings.Cut(kv, "=")
		n, _ := strconv.Atoi(v)
		switch k {
		case "m":
			m = uint32(n)
		case "t":
			t = uint32(n)
		case "p":
			p = uint32(n)
		}
	}
	if m != phcMemory || t != phcTime || p != phcParallel {
		return fmt.Errorf("argon2 params must be m=%d,t=%d,p=%d", phcMemory, phcTime, phcParallel)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		salt, err = base64.StdEncoding.DecodeString(parts[4])
	}
	if err != nil {
		return fmt.Errorf("salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		want, err = base64.StdEncoding.DecodeString(parts[5])
	}
	if err != nil {
		return fmt.Errorf("hash: %w", err)
	}
	if len(want) == 0 {
		return fmt.Errorf("empty PHC hash rejected")
	}
	got := argon2.IDKey(password, salt, t, m, uint8(p), uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return fmt.Errorf("mismatch")
	}
	return nil
}

func compareConstant(a, b []byte) error {
	a = []byte(strings.TrimSpace(string(a)))
	ha := sha256.Sum256(a)
	hb := sha256.Sum256(b)
	if subtle.ConstantTimeCompare(ha[:], hb[:]) != 1 {
		return fmt.Errorf("mismatch")
	}
	return nil
}

func EncodePHCForTest(password, salt []byte) string {
	return encodePHC(password, salt)
}

func S256ForTest(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func encodePHC(password, salt []byte) string {
	sum := argon2.IDKey(password, salt, phcTime, phcMemory, phcParallel, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		phcMemory, phcTime, phcParallel,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	)
}
