package compiler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func parseSigningKey(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("signing key is not PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key := k.(type) {
		case *rsa.PrivateKey:
			return key.Validate()
		case *ecdsa.PrivateKey:
			return validateEC(key)
		default:
			return fmt.Errorf("unsupported signing key type %T", k)
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key.Validate()
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return validateEC(key)
	}
	return fmt.Errorf("unsupported signing key")
}

func requireRSASigningKey(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("signing key is not PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if _, ok := k.(*rsa.PrivateKey); ok {
			return nil
		}
		return fmt.Errorf("SAML/WS-Fed signing requires an RSA key")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return nil
	}
	return fmt.Errorf("SAML/WS-Fed signing requires an RSA key")
}

func validateEC(k *ecdsa.PrivateKey) error {
	switch k.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
		return nil
	default:
		return fmt.Errorf("unsupported ECDSA signing curve")
	}
}
