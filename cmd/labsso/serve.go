package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/control/mcp"
	"github.com/hilather/go-lab-sso/internal/control/rest"
)

const dest443Help = `Host dest-443 occupancy (if this is a publish/listen failure, not container EACCES/EPERM) is fixed by:
  1. stop/disable the occupant (nginx, caddy, apache, another compose stack), or
  2. extra IP for LAB_PUBLIC_HOST, or
  3. escape LABSSO_HTTPS_PORT (SUTs that cannot set dest port cannot follow).`

func serveCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "path to bootstrap YAML")
	base := fs.String("base-dir", "", "directory for relative secret refs (default: cwd)")
	httpsListen := fs.String("https-listen", "", "HTTPS listen address (default: spec.listeners.https.address)")
	mgmtListen := fs.String("management-listen", "", "management listen address or 'off' (default: spec.listeners.management.address)")
	shutdown := fs.Duration("shutdown-timeout", 5*time.Second, "graceful shutdown timeout")
	pidFile := fs.String("pid-file", "", "optional pid file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" {
		_, _ = fmt.Fprintln(stderr, "labsso serve: --config is required")
		return 2
	}
	if *httpsListen == "off" {
		_, _ = fmt.Fprintln(stderr, "labsso serve: HTTPS dest-443 is required; --https-listen=off is not allowed")
		return 2
	}
	baseDir := *base
	if baseDir == "" {
		baseDir = mustCwd()
	}
	a := app.New(app.Options{
		BootstrapPath: *path,
		BaseDir:       baseDir,
		Env:           compiler.EnvFromOS(),
	})
	if _, err := a.InstallBootstrapFile(); err != nil {
		_, _ = fmt.Fprintf(stderr, "labsso serve: bootstrap: %v\n", err)
		return 1
	}
	snap := a.Store().Load()
	httpsAddr := snap.Canonical.Spec.Listeners.HTTPS.Address
	if *httpsListen != "" {
		httpsAddr = *httpsListen
	}
	mgmtAddr := snap.Canonical.Spec.Listeners.Management.Address
	if *mgmtListen != "" {
		mgmtAddr = *mgmtListen
	}

	if *pidFile != "" {
		if err := os.WriteFile(*pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
			_, _ = fmt.Fprintf(stderr, "labsso serve: pid-file: %v\n", err)
			return 1
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err := runServe(ctx, a, serveRuntime{
		HTTPSAddr: httpsAddr,
		MgmtAddr:  mgmtAddr,
		Shutdown:  *shutdown,
	}, stdout, stderr)
	if err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintf(stderr, "labsso serve: %v\n", err)
		return 1
	}
	return 0
}

type serveRuntime struct {
	HTTPSAddr string
	MgmtAddr  string
	Shutdown  time.Duration
}

func runServe(ctx context.Context, a *app.App, rt serveRuntime, stdout, stderr io.Writer) error {
	snap := a.Store().Load()
	if snap == nil {
		return fmt.Errorf("no snapshot")
	}
	cert, err := tls.X509KeyPair(snap.TLSCert, snap.TLSKey)
	if err != nil {
		return fmt.Errorf("tls key pair: %w", err)
	}
	httpsLn, err := net.Listen("tcp", rt.HTTPSAddr)
	if err != nil {
		return wrapListenErr(rt.HTTPSAddr, err)
	}
	tlsLn := tls.NewListener(httpsLn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	httpsSrv := &http.Server{Handler: a.HTTPSHandler(), ReadHeaderTimeout: 10 * time.Second}

	var mgmtSrv *http.Server
	var mgmtLn net.Listener
	if rt.MgmtAddr != "off" {
		restPath := snap.Canonical.Spec.Listeners.Management.RESTPath
		mcpPath := snap.Canonical.Spec.Listeners.Management.MCPPath
		mux := http.NewServeMux()
		mux.Handle("/", rest.New(a, restPath).Handler())
		ms, err := mcp.New(a, snap.Canonical.Spec.Listeners.Management.MCP.AllowLegacyClients)
		if err != nil {
			_ = httpsLn.Close()
			return err
		}
		if mcpPath == "" {
			mcpPath = "/mcp"
		}
		mux.Handle(mcpPath, ms.Handler())
		mgmtLn, err = net.Listen("tcp", rt.MgmtAddr)
		if err != nil {
			_ = httpsLn.Close()
			return fmt.Errorf("management listen %s: %w", rt.MgmtAddr, err)
		}
		mgmtSrv = &http.Server{Handler: http.NewCrossOriginProtection().Handler(mux), ReadHeaderTimeout: 10 * time.Second}
	}

	a.SetRequireHTTPS(true)
	a.SetHTTPSBound(true)
	_, _ = fmt.Fprintf(stdout, "labsso serve https=%s management=%s issuer=%s\n", rt.HTTPSAddr, rt.MgmtAddr, snap.Issuer)

	errCh := make(chan error, 2)
	go func() {
		errCh <- httpsSrv.Serve(tlsLn)
	}()
	if mgmtSrv != nil {
		go func() {
			errCh <- mgmtSrv.Serve(mgmtLn)
		}()
	}

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}

	a.SetHTTPSBound(false)
	shutCtx, cancel := context.WithTimeout(context.Background(), rt.Shutdown)
	defer cancel()
	_ = httpsSrv.Shutdown(shutCtx)
	if mgmtSrv != nil {
		_ = mgmtSrv.Shutdown(shutCtx)
	}
	return nil
}

func wrapListenErr(addr string, err error) error {
	if err == nil {
		return nil
	}
	if isPerm(err) {
		return fmt.Errorf("HTTPS bind %s: %w", addr, err)
	}
	return fmt.Errorf("HTTPS bind %s: %w\n\n%s", addr, err, dest443Help)
}

func isPerm(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}
