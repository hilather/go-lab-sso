package compiler

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// labSigningCert synthesizes a lab-only self-signed X.509 certificate from
// signing.keyRef. It is not a second secret and is not a production CA.
func labSigningCert(keyPEM []byte, issuer string, now time.Time) ([]byte, error) {
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(interface{ Public() crypto.PublicKey })
	if !ok {
		return nil, fmt.Errorf("signing key has no public key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	var skid [20]byte
	if rsaK, ok := pub.Public().(*rsa.PublicKey); ok {
		skid = sha1.Sum(x509.MarshalPKCS1PublicKey(rsaK))
	} else if raw, err := x509.MarshalPKIXPublicKey(pub.Public()); err == nil {
		skid = sha1.Sum(raw)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "LabSSO lab signing",
			Organization: []string{"LabSSO"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		SubjectKeyId:          skid[:],
		DNSNames:              []string{"lab.example.net"},
	}
	if issuer != "" {
		tmpl.DNSNames = []string{hostOfIssuer(issuer)}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("lab signing cert: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func hostOfIssuer(iss string) string {
	s := iss
	if i := len("https://"); len(s) > i && s[:i] == "https://" {
		s = s[i:]
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '/' || s[i] == ':' {
			return s[:i]
		}
	}
	return s
}

func parsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("signing key is not PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported signing key type %T", k)
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported signing key")
}
