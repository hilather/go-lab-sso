package compiler

import (
	"crypto/ecdsa"
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
		switch k.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return nil
		default:
			return fmt.Errorf("unsupported signing key type %T", k)
		}
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return nil
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return nil
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
