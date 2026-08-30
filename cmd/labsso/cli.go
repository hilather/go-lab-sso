package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/buildinfo"
	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/config"
)

func validateCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "path to bootstrap YAML")
	base := fs.String("base-dir", "", "directory for relative secret refs (default: cwd)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" {
		_, _ = fmt.Fprintln(stderr, "labsso validate: --config is required")
		return 2
	}
	doc, err := config.LoadFile(*path, config.Options{BaseDir: *base})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "labsso validate: %v\n", err)
		return 1
	}
	if _, err := compiler.Compile(doc, compiler.Options{BaseDir: *base, Env: compiler.EnvFromOS()}); err != nil {
		_, _ = fmt.Fprintf(stderr, "labsso validate: %v\n", err)
		return 1
	}
	rev, err := compiler.RevisionOf(doc)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "labsso validate: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "ok revision=%s\n", rev)
	return 0
}

func canonicalizeCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("canonicalize", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "path to bootstrap YAML")
	format := fs.String("format", "yaml", "yaml or json")
	base := fs.String("base-dir", "", "directory for relative secret refs (default: cwd)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" {
		_, _ = fmt.Fprintln(stderr, "labsso canonicalize: --config is required")
		return 2
	}
	doc, err := config.LoadFile(*path, config.Options{BaseDir: *base})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "labsso canonicalize: %v\n", err)
		return 1
	}
	a := app.New(app.Options{BaseDir: *base})
	switch *format {
	case "yaml", "yml", "":
		b, err := a.Canonicalize(doc)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "labsso canonicalize: %v\n", err)
			return 1
		}
		_, _ = stdout.Write(b)
	case "json":
		config.Normalize(&doc)
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			_, _ = fmt.Fprintf(stderr, "labsso canonicalize: %v\n", err)
			return 1
		}
	default:
		_, _ = fmt.Fprintln(stderr, "labsso canonicalize: --format must be yaml or json")
		return 2
	}
	return 0
}

func versionCmd(stdout io.Writer) int {
	info := buildinfo.Get()
	_, _ = fmt.Fprintf(stdout, "labsso %s commit=%s\n", info.Version, info.Commit)
	return 0
}

func healthcheckCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", "http://127.0.0.1:8080/v1/health/ready", "ready URL")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(*url)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "labsso healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(stderr, "labsso healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "ok")
	return 0
}

func mustCwd() string {
	d, err := os.Getwd()
	if err != nil {
		return ""
	}
	return d
}
