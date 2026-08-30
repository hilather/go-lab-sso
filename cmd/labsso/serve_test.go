package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/compiler"
)

func TestServeTLSAndReady(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	boot := filepath.Join(dir, "config.yaml")
	src, err := os.ReadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(boot, src, 0o644); err != nil {
		t.Fatal(err)
	}
	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mgmtLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpsAddr := httpsLn.Addr().String()
	mgmtAddr := mgmtLn.Addr().String()
	_ = httpsLn.Close()
	_ = mgmtLn.Close()

	a := app.New(app.Options{BootstrapPath: boot, BaseDir: root, Env: compiler.Env{}})
	if _, err := a.InstallBootstrapFile(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runServe(ctx, a, serveRuntime{HTTPSAddr: httpsAddr, MgmtAddr: mgmtAddr, Shutdown: time.Second}, io.Discard, io.Discard)
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 2 * time.Second}
	var ready bool
	for i := 0; i < 40; i++ {
		resp, err := http.Get("http://" + mgmtAddr + "/v1/health/ready")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("ready never 200")
	}
	resp, err := client.Get("https://" + httpsAddr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("data plane status %d (OIDC not implemented yet)", resp.StatusCode)
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not stop")
	}
}
