package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/model"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func serveApp(t *testing.T) *app.App {
	t.Helper()
	root := repoRoot(t)
	a := app.New(app.Options{BootstrapPath: filepath.Join(root, "testdata/config/valid/minimal.yaml"), BaseDir: root})
	if _, err := a.InstallBootstrapFile(); err != nil {
		t.Fatal(err)
	}
	return a
}
func unusedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}
func launchServe(t *testing.T, a *app.App, mgmt string) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	addr := unusedAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- runServe(ctx, a, serveRuntime{HTTPSAddr: addr, MgmtAddr: mgmt, Shutdown: 100 * time.Millisecond}, io.Discard, io.Discard)
	}()
	t.Cleanup(cancel)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			_ = conn.Close()
			return addr, cancel, result
		}
		select {
		case err := <-result:
			t.Fatal(err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("HTTPS never started")
	return "", cancel, result
}
func waitStopped(t *testing.T, cancel context.CancelFunc, result <-chan error, addresses ...string) {
	t.Helper()
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not stop")
	}
	for _, addr := range addresses {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("listener leaked: %v", err)
		}
		_ = ln.Close()
	}
}
func TestIntegrationServeManagementOffDiscovery(t *testing.T) {
	a := serveApp(t)
	addr, cancel, result := launchServe(t, a, "off")
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("https://" + addr + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var discovery map[string]any
	err = json.NewDecoder(response.Body).Decode(&discovery)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || discovery["issuer"] != a.Store().Load().Issuer {
		t.Fatal(discovery, err, response.StatusCode)
	}
	waitStopped(t, cancel, result, addr)
}
func TestIntegrationServeTLSRotationAndFailedApply(t *testing.T) {
	a := serveApp(t)
	addr, cancel, result := launchServe(t, a, "off")
	defer waitStopped(t, cancel, result, addr)
	serial := func() string {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	before := serial()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(12345678), Subject: pkix.Name{CommonName: "rotated"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	apply := func(listeners model.Listeners) error {
		raw, err := json.Marshal(listeners)
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.Apply(auth.AdminActor(), app.ChangeIn{ExpectedRevision: a.Store().Load().Revision, Reason: "TLS rotation test", Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetListeners}, Value: raw}}})
		return err
	}
	listeners := a.Store().Load().Canonical.Spec.Listeners
	listeners.HTTPS.CertRef = certPath
	listeners.HTTPS.KeyRef = keyPath
	if err := apply(listeners); err != nil {
		t.Fatal(err)
	}
	after := serial()
	if before == after || after != "12345678" {
		t.Fatalf("TLS cert did not rotate: %s -> %s", before, after)
	}
	live := a.Store().Load()
	listeners.HTTPS.KeyRef = filepath.Join(repoRoot(t), "testdata/secrets/oidc/signing.pem")
	if err := apply(listeners); err == nil {
		t.Fatal("invalid TLS apply accepted")
	}
	if a.Store().Load() != live || serial() != after {
		t.Fatal("failed apply changed live state/certificate")
	}
}
func TestServeRejectsManagement443BeforeBind(t *testing.T) {
	a := serveApp(t)
	if err := runServe(context.Background(), a, serveRuntime{HTTPSAddr: "127.0.0.1:0", MgmtAddr: "127.0.0.1:443", Shutdown: time.Second}, io.Discard, io.Discard); err == nil {
		t.Fatal("management 443 accepted")
	}
}
func TestServerHasFiniteTimeouts(t *testing.T) {
	server := boundedServer(http.NotFoundHandler())
	if server.ReadTimeout <= 0 || server.ReadHeaderTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes <= 0 {
		t.Fatal("server lacks bounds")
	}
}
func TestIntegrationShutdownClosesActiveConnection(t *testing.T) {
	a := serveApp(t)
	addr, cancel, result := launchServe(t, a, "off")
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "POST /login HTTP/1.1\r\nHost: lab.example\r\nContent-Length: 1000\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nx="); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	waitStopped(t, cancel, result, addr)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("active connection left open")
	}
}

func TestIntegrationUnexpectedServeFailureCleansBothListeners(t *testing.T) {
	a := serveApp(t)
	httpsAddr, mgmtAddr := unusedAddr(t), unusedAddr(t)
	listeners := make(chan net.Listener, 2)
	listen := func(network, address string) (net.Listener, error) {
		ln, err := net.Listen(network, address)
		if err == nil {
			listeners <- ln
		}
		return ln, err
	}
	result := make(chan error, 1)
	go func() {
		result <- runServe(context.Background(), a, serveRuntime{HTTPSAddr: httpsAddr, MgmtAddr: mgmtAddr, Shutdown: time.Second, listen: listen}, io.Discard, io.Discard)
	}()
	var first net.Listener
	select {
	case first = <-listeners:
	case <-time.After(time.Second):
		t.Fatal("HTTPS did not bind")
	}
	select {
	case <-listeners:
	case <-time.After(time.Second):
		_ = first.Close()
		t.Fatal("management did not bind")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("unexpected listener failure hidden")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve failure did not exit")
	}
	if _, ready := a.HealthReady(); ready {
		t.Fatal("failed service remains ready")
	}
	for _, addr := range []string{httpsAddr, mgmtAddr} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal("listener leaked", err)
		}
		_ = ln.Close()
	}
}
