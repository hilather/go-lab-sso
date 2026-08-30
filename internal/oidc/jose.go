package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type signer struct {
	jwk    jose.JSONWebKey
	signer jose.Signer
	alg    jose.SignatureAlgorithm
	keyID  string
}

func newSigner(pemBytes []byte) (*signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("signing key is not PEM")
	}
	var key crypto.PrivateKey
	var err error
	if k, e := x509.ParsePKCS8PrivateKey(block.Bytes); e == nil {
		key = k
	} else if k, e := x509.ParsePKCS1PrivateKey(block.Bytes); e == nil {
		key = k
	} else if k, e := x509.ParseECPrivateKey(block.Bytes); e == nil {
		key = k
	} else {
		return nil, fmt.Errorf("unsupported signing key")
	}
	var alg jose.SignatureAlgorithm
	var pub crypto.PublicKey
	switch k := key.(type) {
	case *rsa.PrivateKey:
		alg = jose.RS256
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		alg = jose.ES256
		pub = &k.PublicKey
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
	kid := "labsso-1"
	jwk := jose.JSONWebKey{Key: pub, KeyID: kid, Algorithm: string(alg), Use: "sig"}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		return nil, err
	}
	return &signer{jwk: jwk, signer: sig, alg: alg, keyID: kid}, nil
}

func (s *signer) mint(iss, sub, aud, nonce string, ttl time.Duration, extra map[string]any) (string, error) {
	now := time.Now()
	claims := jwt.Claims{
		Issuer:   iss,
		Subject:  sub,
		Audience: jwt.Audience{aud},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(ttl)),
	}
	builder := jwt.Signed(s.signer).Claims(claims)
	if nonce != "" {
		builder = builder.Claims(map[string]any{"nonce": nonce})
	}
	if extra != nil {
		builder = builder.Claims(extra)
	}
	return builder.Serialize()
}

func (s *signer) publicJWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{s.jwk.Public()}}
}

func parseAndVerify(token string, jwk jose.JSONWebKey, iss string, accessOnly bool) (jwt.Claims, error) {
	c, _, err := parseAndVerifyExtra(token, jwk, iss, accessOnly)
	return c, err
}

func parseAndVerifyExtra(token string, jwk jose.JSONWebKey, iss string, accessOnly bool) (jwt.Claims, map[string]any, error) {
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		return jwt.Claims{}, nil, err
	}
	var c jwt.Claims
	var extra map[string]any
	if err := tok.Claims(jwk.Key, &c, &extra); err != nil {
		return jwt.Claims{}, nil, err
	}
	if err := c.Validate(jwt.Expected{Issuer: iss, Time: time.Now()}); err != nil {
		return jwt.Claims{}, nil, err
	}
	if accessOnly {
		use, _ := extra["token_use"].(string)
		if use != "access" {
			return jwt.Claims{}, nil, fmt.Errorf("not an access token")
		}
	}
	if extra == nil {
		extra = map[string]any{}
	}
	return c, extra, nil
}
