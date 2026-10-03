package loginui

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/hilather/go-lab-sso/internal/password"
	"golang.org/x/crypto/argon2"
)

const (
	phcMemory   = 65536
	phcTime     = 3
	phcParallel = 4
)

func verifyPHC(phc string, provided []byte) error {
	c, err := password.Parse([]byte(phc), true)
	if err != nil {
		return err
	}
	return c.Verify(provided)
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
