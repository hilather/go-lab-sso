package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func verifyPKCE(challenge, method, verifier string) bool {
	if method != "S256" || !validChallenge(challenge) || !validVerifier(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return strings.TrimRight(got, "=") == strings.TrimRight(challenge, "=")
}

func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.ContainsRune("-._~", c):
		default:
			return false
		}
	}
	return true
}
func validChallenge(v string) bool {
	b, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == v
}
