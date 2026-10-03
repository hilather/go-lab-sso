package model

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode"
)

func ValidHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
			if !valid {
				return false
			}
		}
	}
	return true
}
func ValidPort(port string) bool {
	if port == "" {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}
func ValidateURI(raw string, httpsOnly bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(raw, "*\\#") || strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return fmt.Errorf("invalid recipient URI")
	}
	if u.Scheme == "https" || u.Scheme == "http" {
		if httpsOnly && u.Scheme != "https" {
			return fmt.Errorf("HTTPS required")
		}
		if !ValidHost(u.Hostname()) || (u.Port() != "" && !ValidPort(u.Port())) || strings.HasSuffix(u.Host, ":") {
			return fmt.Errorf("invalid recipient host/port")
		}
		return nil
	}
	if httpsOnly || u.Scheme == "javascript" || u.Scheme == "data" || u.Scheme == "file" || !strings.Contains(u.Scheme, ".") || (u.Path == "" && u.Opaque == "") {
		return fmt.Errorf("unsupported native redirect scheme")
	}
	return nil
}
func ValidateListenAddress(raw string, management bool) error {
	host, port, err := net.SplitHostPort(raw)
	if err != nil || (port != "0" && !ValidPort(port)) || (host != "" && !ValidHost(host)) {
		return fmt.Errorf("invalid listen address")
	}
	n, _ := strconv.Atoi(port)
	if management && n == 443 {
		return fmt.Errorf("management listener must not use port 443")
	}
	return nil
}
func ValidateManagementPaths(rest, mcp string) error {
	for _, p := range []string{rest, mcp} {
		if p == "/" || !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsAny(p, "{}%?#\\ \t\r\n") || strings.ContainsFunc(p, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) || strings.HasSuffix(p, "/") {
			return fmt.Errorf("management paths must be literal clean non-root paths")
		}
	}
	if rest == mcp || strings.HasPrefix(rest, mcp+"/") || strings.HasPrefix(mcp, rest+"/") {
		return fmt.Errorf("management paths must not overlap")
	}
	for _, p := range []string{rest, mcp} {
		for _, reserved := range []string{"/app.js"} {
			if p == reserved || strings.HasPrefix(p, reserved+"/") || strings.HasPrefix(reserved, p+"/") {
				return fmt.Errorf("management path overlaps reserved route")
			}
		}
	}
	return nil
}
func validSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
		if !valid {
			return false
		}
	}
	return true
}
