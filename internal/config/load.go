package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/totp"
	"gopkg.in/yaml.v3"
)

type Options struct {
	BaseDir string
}

func LoadFile(path string, opt Options) (model.Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return model.Document{}, err
	}
	return Load(b, opt)
}

func Load(raw []byte, opt Options) (model.Document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var doc model.Document
	if err := dec.Decode(&doc); err != nil {
		return model.Document{}, fmt.Errorf("decode: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return model.Document{}, fmt.Errorf("trailing YAML document rejected")
		}
		return model.Document{}, fmt.Errorf("decode: %w", err)
	}
	if err := rejectInlineSecrets(raw); err != nil {
		return model.Document{}, err
	}
	Normalize(&doc)
	if err := doc.ValidateIDs(); err != nil {
		return model.Document{}, err
	}
	if err := ValidateSecretRefs(doc, opt.BaseDir); err != nil {
		return model.Document{}, err
	}
	return doc, nil
}

func Normalize(doc *model.Document) {
	if doc.Spec.Listeners.HTTPS.Address == "" {
		doc.Spec.Listeners.HTTPS.Address = ":10443"
	}
	if doc.Spec.Listeners.Management.Address == "" {
		doc.Spec.Listeners.Management.Address = ":8080"
	}
	if doc.Spec.Listeners.Management.RESTPath == "" {
		doc.Spec.Listeners.Management.RESTPath = "/v1"
	}
	if doc.Spec.Listeners.Management.MCPPath == "" {
		doc.Spec.Listeners.Management.MCPPath = "/mcp"
	}
	if doc.Spec.Profile.Vendor == "" {
		doc.Spec.Profile.Vendor = "generic"
	}
	if doc.Spec.Protocols.OIDC.Enabled == nil {
		doc.Spec.Protocols.OIDC.Enabled = model.Ptr(true)
	}
	if doc.Spec.Protocols.SAML.Enabled == nil {
		doc.Spec.Protocols.SAML.Enabled = model.Ptr(false)
	}
	if doc.Spec.Protocols.WSFed.Enabled == nil {
		doc.Spec.Protocols.WSFed.Enabled = model.Ptr(false)
	}
	if doc.Spec.Auth.SessionTTL == 0 {
		doc.Spec.Auth.SessionTTL = model.Duration(0)
	}
	if doc.Spec.Auth.MFA.Mode == "" {
		doc.Spec.Auth.MFA.Mode = "never"
	}
	if doc.Spec.GroupOverage.OktaFailAt == 0 {
		doc.Spec.GroupOverage.OktaFailAt = 100
	}
	if doc.Spec.GroupOverage.GenericCap == 0 {
		doc.Spec.GroupOverage.GenericCap = 200
	}
	if doc.Spec.UI.Enabled == nil {
		doc.Spec.UI.Enabled = model.Ptr(true)
	}
	if doc.Spec.Clients == nil {
		doc.Spec.Clients = []model.Client{}
	}
	if doc.Spec.Users == nil {
		doc.Spec.Users = []model.User{}
	}
	if doc.Spec.Groups == nil {
		doc.Spec.Groups = []model.Group{}
	}
}

func CanonicalYAML(doc model.Document) ([]byte, error) {
	out := doc
	Normalize(&out)
	return yaml.Marshal(out)
}

func rejectInlineSecrets(raw []byte) error {
	s := string(raw)
	if strings.Contains(s, "-----BEGIN ") {
		return fmt.Errorf("inline PEM rejected; use file refs")
	}
	return nil
}

func ValidateSecretRefs(doc model.Document, base string) error {
	refs := []string{
		doc.Spec.Listeners.HTTPS.CertRef,
		doc.Spec.Listeners.HTTPS.KeyRef,
		doc.Spec.Signing.KeyRef,
		doc.Spec.Access.TokenRef,
	}
	for _, u := range doc.Spec.Users {
		if strings.Contains(u.PasswordRef, "\n") || strings.Contains(u.PasswordHashRef, "\n") {
			return fmt.Errorf("inline password material rejected")
		}
		if strings.Contains(u.TOTPSecretRef, "\n") {
			return fmt.Errorf("inline totp material rejected")
		}
		if u.PasswordRef != "" {
			refs = append(refs, u.PasswordRef)
		}
		if u.PasswordHashRef != "" {
			refs = append(refs, u.PasswordHashRef)
		}
		if u.TOTPSecretRef != "" {
			refs = append(refs, u.TOTPSecretRef)
		}
	}
	for _, c := range doc.Spec.Clients {
		if c.SecretRef != "" {
			refs = append(refs, c.SecretRef)
		}
	}
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		p := ref
		if !filepath.IsAbs(p) && base != "" {
			p = filepath.Join(base, p)
		}
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("secret ref %q: %w", ref, err)
		}
	}
	for _, u := range doc.Spec.Users {
		if u.TOTPSecretRef == "" {
			continue
		}
		p := u.TOTPSecretRef
		if !filepath.IsAbs(p) && base != "" {
			p = filepath.Join(base, p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("totpSecretRef %q: %w", u.TOTPSecretRef, err)
		}
		if _, err := totp.ParseSecret(b); err != nil {
			return fmt.Errorf("totpSecretRef %q: %w", u.TOTPSecretRef, err)
		}
	}
	return nil
}
