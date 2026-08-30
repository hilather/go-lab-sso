package compiler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hilather/go-lab-sso/internal/config"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/snapshot"
)

type Options struct {
	Env               Env
	BaseDir           string
	Generation        int
	BootstrapRevision string
	CompiledAt        time.Time
}

func Compile(doc model.Document, opt Options) (*snapshot.Snapshot, error) {
	snap, err := compile(doc, opt)
	if err != nil {
		if domainerr.CodeOf(err) != "" {
			return nil, err
		}
		return nil, domainerr.Validation(err.Error())
	}
	return snap, nil
}

func compile(doc model.Document, opt Options) (*snapshot.Snapshot, error) {
	config.Normalize(&doc)
	if err := doc.ValidateIDs(); err != nil {
		return nil, err
	}
	issuer, err := ResolveIssuer(doc.Spec.Issuer, opt.Env)
	if err != nil {
		return nil, err
	}
	doc.Spec.Issuer = issuer

	tlsCert, err := readRef(opt.BaseDir, doc.Spec.Listeners.HTTPS.CertRef, "listeners.https.certRef")
	if err != nil {
		return nil, err
	}
	tlsKey, err := readRef(opt.BaseDir, doc.Spec.Listeners.HTTPS.KeyRef, "listeners.https.keyRef")
	if err != nil {
		return nil, err
	}
	signing, err := readRef(opt.BaseDir, doc.Spec.Signing.KeyRef, "signing.keyRef")
	if err != nil {
		return nil, err
	}
	token, err := readRef(opt.BaseDir, doc.Spec.Access.TokenRef, "access.tokenRef")
	if err != nil {
		return nil, err
	}
	token = bytes.TrimSpace(token)
	if len(token) == 0 {
		return nil, fmt.Errorf("access.tokenRef is empty")
	}
	if err := parseSigningKey(signing); err != nil {
		return nil, fmt.Errorf("signing.keyRef: %w", err)
	}
	if err := config.ValidateSecretRefs(doc, opt.BaseDir); err != nil {
		return nil, err
	}

	rev, err := RevisionOf(doc)
	if err != nil {
		return nil, err
	}
	boot := opt.BootstrapRevision
	if boot == "" {
		boot = rev
	}
	gen := opt.Generation
	if gen == 0 {
		gen = 1
	}
	at := opt.CompiledAt
	if at.IsZero() {
		at = time.Now()
	}

	clientsByID := make(map[string]model.Client, len(doc.Spec.Clients))
	clientsByClientID := make(map[string]model.Client, len(doc.Spec.Clients))
	clientSecrets := make(map[string][]byte, len(doc.Spec.Clients))
	for _, c := range doc.Spec.Clients {
		clientsByID[c.ID] = c
		key := c.ClientID
		if key == "" {
			key = c.ID
		}
		clientsByClientID[key] = c
		if c.SecretRef != "" {
			sec, err := readRef(opt.BaseDir, c.SecretRef, "clients.secretRef")
			if err != nil {
				return nil, err
			}
			sec = bytes.TrimSpace(sec)
			if len(sec) == 0 {
				return nil, fmt.Errorf("clients.secretRef %q is empty", c.SecretRef)
			}
			clientSecrets[key] = sec
		}
	}
	usersByID := make(map[string]model.User, len(doc.Spec.Users))
	for _, u := range doc.Spec.Users {
		usersByID[u.ID] = u
	}
	groupsByID := make(map[string]model.Group, len(doc.Spec.Groups))
	for _, g := range doc.Spec.Groups {
		groupsByID[g.ID] = g
	}

	return &snapshot.Snapshot{
		Canonical:         cloneDoc(doc),
		Revision:          rev,
		BootstrapRevision: boot,
		Generation:        gen,
		CompiledAt:        at,
		Issuer:            issuer,
		TLSCert:           tlsCert,
		TLSKey:            tlsKey,
		SigningKey:        signing,
		AccessToken:       token,
		ClientSecrets:     clientSecrets,
		ClientsByID:       clientsByID,
		ClientsByClientID: clientsByClientID,
		UsersByID:         usersByID,
		GroupsByID:        groupsByID,
	}, nil
}

func RevisionOf(doc model.Document) (string, error) {
	b, err := config.CanonicalYAML(doc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func readRef(base, ref, field string) ([]byte, error) {
	if ref == "" {
		return nil, fmt.Errorf("%s is required", field)
	}
	p := ref
	if !filepath.IsAbs(p) && base != "" {
		p = filepath.Join(base, p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("%s %q: %w", field, ref, err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%s %q is empty", field, ref)
	}
	return b, nil
}

func CloneDocument(doc model.Document) *model.Document {
	return cloneDoc(doc)
}

func cloneDoc(doc model.Document) *model.Document {
	out := doc
	out.Spec.Clients = cloneClients(doc.Spec.Clients)
	out.Spec.Users = cloneUsers(doc.Spec.Users)
	out.Spec.Groups = append([]model.Group(nil), doc.Spec.Groups...)
	out.Spec.Protocols.OIDC.Enabled = cloneBool(doc.Spec.Protocols.OIDC.Enabled)
	out.Spec.Protocols.SAML.Enabled = cloneBool(doc.Spec.Protocols.SAML.Enabled)
	out.Spec.Protocols.WSFed.Enabled = cloneBool(doc.Spec.Protocols.WSFed.Enabled)
	out.Spec.UI.Enabled = cloneBool(doc.Spec.UI.Enabled)
	return &out
}

func cloneBool(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneClients(in []model.Client) []model.Client {
	out := make([]model.Client, len(in))
	for i, c := range in {
		out[i] = c.Clone()
	}
	return out
}

func cloneUsers(in []model.User) []model.User {
	out := make([]model.User, len(in))
	for i, u := range in {
		out[i] = u.Clone()
	}
	return out
}
