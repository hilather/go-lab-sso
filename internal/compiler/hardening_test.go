package compiler_test

import (
	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/config"
	"github.com/hilather/go-lab-sso/internal/model"
	"os"
	"path/filepath"
	"testing"
)

func TestReviewSnapshotIndexAliasing(t *testing.T) {
	root := repoRoot(t)
	d, e := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if e != nil {
		t.Fatal(e)
	}
	d.Spec.Clients = []model.Client{{ID: "c", Public: true, RedirectURIs: []string{"https://original.example/cb"}}}
	d.Spec.Users = []model.User{{ID: "u", Username: "u", PasswordRef: "testdata/secrets/users/alice.password", Enabled: model.Ptr(true)}}
	s, e := compiler.Compile(d, compiler.Options{BaseDir: root})
	if e != nil {
		t.Fatal(e)
	}
	d.Spec.Clients[0].RedirectURIs[0] = "https://changed.example/cb"
	*d.Spec.Users[0].Enabled = false
	if s.ClientsByID["c"].RedirectURIs[0] != "https://original.example/cb" || !*s.UsersByID["u"].Enabled {
		t.Fatalf("snapshot aliases caller: client=%v enabled=%v canonical=%v", s.ClientsByID["c"].RedirectURIs, *s.UsersByID["u"].Enabled, s.Canonical.Spec.Clients[0].RedirectURIs)
	}
}
func TestReviewCompileRejectsBadTLS(t *testing.T) {
	root := repoRoot(t)
	d, e := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "bad.crt")
	if e = os.WriteFile(p, []byte("not a cert"), 0600); e != nil {
		t.Fatal(e)
	}
	d.Spec.Listeners.HTTPS.CertRef = p
	if _, e = compiler.Compile(d, compiler.Options{BaseDir: root}); e == nil {
		t.Fatal("compiler accepts invalid TLS certificate")
	}
}
func TestReviewCompileRejectsBrokenEndpoints(t *testing.T) {
	root := repoRoot(t)
	d, e := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if e != nil {
		t.Fatal(e)
	}
	for _, iss := range []string{"not a URL", "http://lab.example.net", "https://lab.example.net/?q=x", "https://lab.example.net/path"} {
		t.Run(iss, func(t *testing.T) {
			d.Spec.Issuer = iss
			if _, e := compiler.Compile(d, compiler.Options{BaseDir: root}); e == nil {
				t.Fatal("compiler accepts unroutable/invalid issuer")
			}
		})
	}
}

func TestIssuerIPv6AndInvalidEnvironment(t *testing.T) {
	for _, host := range []string{"::1", "[::1]"} {
		got, err := compiler.ResolveIssuer("https://[::1]:8443", compiler.Env{PublicHost: host, HTTPSPort: "8443"})
		if err != nil || got != "https://[::1]:8443" {
			t.Fatal(got, err)
		}
	}
	for _, env := range []compiler.Env{{PublicHost: "host/path"}, {PublicHost: "host:443"}, {PublicHost: "lab.example.net", HTTPSPort: "65536"}, {PublicHost: "lab.example.net", HTTPSPort: "http"}} {
		if _, err := compiler.ResolveIssuer("https://lab.example.net", env); err == nil {
			t.Fatal(env)
		}
	}
	for _, issuer := range []string{"https://lab.example.net/", "https://lab.example.net?", "https://user@lab.example.net", "https://lab.example.net:0"} {
		if _, err := compiler.ResolveIssuer(issuer, compiler.Env{}); err == nil {
			t.Fatal(issuer)
		}
	}
}
func TestCompiledPasswordDetachedFromFile(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	doc.Spec.Users = []model.User{{ID: "u", Username: "alice", PasswordRef: path}}
	snap, err := compiler.Compile(doc, compiler.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	cred, ok := snap.Password("u")
	if !ok || cred.Verify([]byte("original")) != nil || cred.Verify([]byte("changed")) == nil {
		t.Fatal("credential changed outside compile")
	}
	doc.Spec.Users[0].PasswordRef = ""
	doc.Spec.Users[0].PasswordHashRef = path
	if _, err := compiler.Compile(doc, compiler.Options{BaseDir: root}); err == nil {
		t.Fatal("plaintext hash ref accepted")
	}
}

func TestCompileRejectsBadOrMismatchedTLSKey(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(bad, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	doc.Spec.Listeners.HTTPS.KeyRef = bad
	if _, err := compiler.Compile(doc, compiler.Options{BaseDir: root}); err == nil {
		t.Fatal("invalid TLS key accepted")
	}
	doc.Spec.Listeners.HTTPS.KeyRef = "testdata/secrets/oidc/signing.pem"
	if _, err := compiler.Compile(doc, compiler.Options{BaseDir: root}); err == nil {
		t.Fatal("mismatched TLS key accepted")
	}
}
