package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: labsso <validate|canonicalize|serve|healthcheck|version> [flags]")
		return 2
	}
	switch args[0] {
	case "validate":
		return validateCmd(args[1:], stdout, stderr)
	case "canonicalize":
		return canonicalizeCmd(args[1:], stdout, stderr)
	case "serve":
		return serveCmd(args[1:], stdout, stderr)
	case "healthcheck":
		return healthcheckCmd(args[1:], stdout, stderr)
	case "version":
		return versionCmd(stdout)
	default:
		_, _ = fmt.Fprintf(stderr, "labsso: unknown command %q\n", args[0])
		return 2
	}
}
