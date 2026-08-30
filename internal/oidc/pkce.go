package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func verifyPKCE(challenge, method, verifier string) bool {
	if method != "S256" || challenge == "" || verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return strings.TrimRight(got, "=") == strings.TrimRight(challenge, "=")
}
