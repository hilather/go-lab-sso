// Package password compiles credentials without retaining mutable file references.
package password

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

const (
	argonTime        = 3
	argonMemory      = 65536
	argonParallelism = 4
	argonKeyLen      = 32
)

type Credential struct {
	plain  [32]byte
	salt   string
	digest string
	hashed bool
	dummy  bool
}

// Dummy returns a credential that never accepts a password and uses the same
// verification cost as parsed credentials of the requested kind. Its salt and
// digest are public padding material, not an account secret.
func Dummy(hashed bool) Credential {
	if !hashed {
		return Credential{dummy: true}
	}
	return Credential{hashed: true, dummy: true, salt: "labsso-dummy-salt", digest: strings.Repeat("\x00", argonKeyLen)}
}

func Parse(raw []byte, hashed bool) (Credential, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return Credential{}, fmt.Errorf("empty password credential")
	}
	if !hashed {
		return Credential{plain: sha256.Sum256([]byte(s))}, nil
	}
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return Credential{}, fmt.Errorf("passwordHashRef requires Argon2id PHC v=19 m=65536,t=3,p=4")
	}
	params := map[string]string{}
	for _, part := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || params[k] != "" {
			return Credential{}, fmt.Errorf("malformed or duplicate PHC parameters")
		}
		params[k] = v
	}
	if len(params) != 3 || params["m"] != "65536" || params["t"] != "3" || params["p"] != "4" {
		return Credential{}, fmt.Errorf("unsupported PHC parameters")
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return Credential{}, fmt.Errorf("invalid PHC salt (8..64 bytes required)")
	}
	digest, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(digest) != 32 {
		return Credential{}, fmt.Errorf("invalid PHC digest (32 bytes required)")
	}
	return Credential{salt: string(salt), digest: string(digest), hashed: true}, nil
}
func (c Credential) Verify(provided []byte) error {
	return c.verify(provided, argon2.IDKey)
}

func (c Credential) verify(provided []byte, derive func([]byte, []byte, uint32, uint32, uint8, uint32) []byte) error {
	var match int
	if c.hashed {
		got := derive(provided, []byte(c.salt), argonTime, argonMemory, argonParallelism, argonKeyLen)
		match = subtle.ConstantTimeCompare(got, []byte(c.digest))
	} else {
		got := sha256.Sum256(provided)
		match = subtle.ConstantTimeCompare(got[:], c.plain[:])
	}
	if match == 1 && !c.dummy {
		return nil
	}
	return fmt.Errorf("mismatch")
}
