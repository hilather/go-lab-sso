package saml

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAuthnRequestShape(t *testing.T) {
	good := `<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="x" Version="2.0"><a:Issuer xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion">sp</a:Issuer></p:AuthnRequest>`
	for _, raw := range []string{strings.ReplaceAll(good, "AuthnRequest", "Other"), strings.Replace(good, "Version=\"2.0\"", "Version=\"9.9\"", 1), strings.Replace(good, "urn:oasis:names:tc:SAML:2.0:assertion", "wrong", 1), good + good} {
		if _, err := decodeSAMLRequest(base64.StdEncoding.EncodeToString([]byte(raw)), false); err == nil {
			t.Fatal("accepted malformed request", raw)
		}
	}
	if _, err := decodeSAMLRequest(base64.StdEncoding.EncodeToString([]byte(good)), false); err != nil {
		t.Fatal(err)
	}
}
func TestMetadataShape(t *testing.T) {
	good := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="sp"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sut.example/acs" index="0"/></SPSSODescriptor></EntityDescriptor>`
	if _, acs, err := ParseSPSSO(good); err != nil || len(acs) != 1 {
		t.Fatal(acs, err)
	}
	for _, raw := range []string{good + good, strings.Replace(good, "urn:oasis:names:tc:SAML:2.0:metadata", "wrong", 1), strings.Replace(good, "HTTP-POST", "HTTP-Artifact", 1), strings.Replace(good, "https://sut.example/acs", "https:///acs", 1)} {
		if _, _, err := ParseSPSSO(raw); err == nil {
			t.Fatal("accepted malformed metadata", raw)
		}
	}
}
