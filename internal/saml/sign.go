package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/snapshot"
)

const (
	nsProto      = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssert     = "urn:oasis:names:tc:SAML:2.0:assertion"
	statusOK     = "urn:oasis:names:tc:SAML:2.0:status:Success"
	statusDeny   = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	nameIDFmt    = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	bearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	passwordAC   = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
)

type memKeyStore struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func (m memKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return m.key, m.cert.Raw, nil
}

func keyStore(snap *snapshot.Snapshot) (memKeyStore, error) {
	block, _ := pem.Decode(snap.SigningKey)
	if block == nil {
		return memKeyStore{}, fmt.Errorf("signing key is not PEM")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return memKeyStore{}, fmt.Errorf("SAML signing requires RSA key")
		}
		key = rk
	} else if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else {
		return memKeyStore{}, fmt.Errorf("SAML signing requires RSA key")
	}
	cb, _ := pem.Decode(snap.SigningCert)
	if cb == nil {
		return memKeyStore{}, fmt.Errorf("lab signing cert missing")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return memKeyStore{}, err
	}
	return memKeyStore{key: key, cert: cert}, nil
}

func certB64(snap *snapshot.Snapshot) string {
	cb, _ := pem.Decode(snap.SigningCert)
	if cb == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(cb.Bytes)
}

func buildResponse(snap *snapshot.Snapshot, user model.User, acs, inResponseTo, audience string, now time.Time, success bool) (string, error) {
	ks, err := keyStore(snap)
	if err != nil {
		return "", err
	}
	iss := strings.TrimRight(snap.Issuer, "/")
	respID := "_" + randomHex()
	assertID := "_" + randomHex()
	notOnOrAfter := now.Add(5 * time.Minute).UTC().Format(time.RFC3339)
	notBefore := now.Add(-time.Minute).UTC().Format(time.RFC3339)
	instant := now.UTC().Format(time.RFC3339)

	resp := etree.NewElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsProto)
	resp.CreateAttr("xmlns:saml", nsAssert)
	resp.CreateAttr("ID", respID)
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", instant)
	resp.CreateAttr("Destination", acs)
	if inResponseTo != "" {
		resp.CreateAttr("InResponseTo", inResponseTo)
	}
	issuer := resp.CreateElement("saml:Issuer")
	issuer.SetText(iss)
	st := resp.CreateElement("samlp:Status")
	code := st.CreateElement("samlp:StatusCode")
	if success {
		code.CreateAttr("Value", statusOK)
	} else {
		code.CreateAttr("Value", statusDeny)
	}
	if success {
		assert := resp.CreateElement("saml:Assertion")
		assert.CreateAttr("xmlns:saml", nsAssert)
		assert.CreateAttr("ID", assertID)
		assert.CreateAttr("Version", "2.0")
		assert.CreateAttr("IssueInstant", instant)
		assert.CreateElement("saml:Issuer").SetText(iss)

		subj := assert.CreateElement("saml:Subject")
		nid := subj.CreateElement("saml:NameID")
		nid.CreateAttr("Format", nameIDFmt)
		nid.SetText(user.Username)
		sc := subj.CreateElement("saml:SubjectConfirmation")
		sc.CreateAttr("Method", bearerMethod)
		scd := sc.CreateElement("saml:SubjectConfirmationData")
		scd.CreateAttr("NotOnOrAfter", notOnOrAfter)
		scd.CreateAttr("Recipient", acs)
		if inResponseTo != "" {
			scd.CreateAttr("InResponseTo", inResponseTo)
		}

		cond := assert.CreateElement("saml:Conditions")
		cond.CreateAttr("NotBefore", notBefore)
		cond.CreateAttr("NotOnOrAfter", notOnOrAfter)
		aud := cond.CreateElement("saml:AudienceRestriction")
		aud.CreateElement("saml:Audience").SetText(audience)

		authn := assert.CreateElement("saml:AuthnStatement")
		authn.CreateAttr("AuthnInstant", instant)
		authn.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(passwordAC)

		attrs := assert.CreateElement("saml:AttributeStatement")
		addAttr(attrs, "uid", user.Username)
		if user.Email != "" {
			addAttr(attrs, "mail", user.Email)
		}
		for _, n := range groupNames(snap, user) {
			addAttr(attrs, "groups", n)
		}

		ctx := dsig.NewDefaultSigningContext(ks)
		ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		signed, err := ctx.SignEnveloped(assert)
		if err != nil {
			return "", err
		}
		resp.RemoveChild(assert)
		resp.AddChild(signed)
	}

	doc := etree.NewDocument()
	doc.SetRoot(resp)
	out, err := doc.WriteToString()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(out)), nil
}

func addAttr(parent *etree.Element, name, value string) {
	a := parent.CreateElement("saml:Attribute")
	a.CreateAttr("Name", name)
	av := a.CreateElement("saml:AttributeValue")
	av.SetText(value)
}

func groupNames(snap *snapshot.Snapshot, user model.User) []string {
	names := make([]string, 0, len(user.GroupIDs))
	for _, gid := range user.GroupIDs {
		if g, ok := snap.GroupsByID[gid]; ok && g.Name != "" {
			names = append(names, g.Name)
		} else {
			names = append(names, gid)
		}
	}
	return names
}

func randomHex() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
