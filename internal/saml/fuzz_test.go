package saml

import (
	"encoding/base64"
	"testing"
)

func FuzzSAMLMetadata(f *testing.F) {
	f.Add(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="sp"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sut.example/acs" index="0"/></SPSSODescriptor></EntityDescriptor>`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxSAMLBytes+1 {
			return
		}
		_, _, _ = ParseSPSSO(raw)
	})
}
func FuzzSAMLAuthnRequest(f *testing.F) {
	f.Add([]byte(`<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="x" Version="2.0"><a:Issuer xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion">sp</a:Issuer></p:AuthnRequest>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxSAMLBytes+1 {
			return
		}
		_, _ = decodeSAMLRequest(base64.StdEncoding.EncodeToString(raw), false)
	})
}
