package auth

import (
	"crypto/subtle"
	"net"
	"strings"

	"github.com/hilather/go-lab-sso/internal/capabilities"
	"github.com/hilather/go-lab-sso/internal/domainerr"
)

const (
	ClassLoopback = "loopback"
	ClassBearer   = "bearer"
	ClassCookie   = "cookie"
	ProfileDev    = "dev-loopback-unauth"
	CookieSession = "labsso_session"
	HeaderCSRF    = "X-LabSSO-CSRF"
)

type Actor struct {
	ID     string
	Class  string
	Scopes []string
}

func AdminActor() Actor {
	return Actor{ID: "admin", Class: ClassLoopback, Scopes: []string{capabilities.ScopeAdmin}}
}

func (a Actor) HasScope(scope string) bool {
	if scope == "" {
		return true
	}
	for _, s := range a.Scopes {
		if s == capabilities.ScopeAdmin || s == scope {
			return true
		}
	}
	return false
}

func Authorize(actor Actor, cap capabilities.Capability) error {
	if len(cap.RequiredScopes) == 0 {
		return nil
	}
	for _, s := range cap.RequiredScopes {
		if actor.HasScope(s) {
			return nil
		}
	}
	return domainerr.Forbidden("missing scope for " + cap.ID)
}

func IsLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func LoopbackHostAllowed(remoteAddr, host string) bool {
	if !IsLoopback(remoteAddr) {
		return true
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch strings.ToLower(host) {
	case "", "localhost", "127.0.0.1", "::1", "[::1]", "example.com":
		return true
	default:
		return false
	}
}

func ParseBearer(header string) string {
	const p = "Bearer "
	if len(header) < len(p) || !strings.EqualFold(header[:len(p)], p) {
		return ""
	}
	return strings.TrimSpace(header[len(p):])
}

func Authenticate(remoteAddr, authzHeader string, token []byte) (Actor, error) {
	raw := ParseBearer(authzHeader)
	if raw != "" {
		if len(token) == 0 || subtle.ConstantTimeCompare([]byte(raw), token) != 1 {
			return Actor{}, domainerr.Unauthorized("invalid bearer token")
		}
		return Actor{ID: "bearer", Class: ClassBearer, Scopes: []string{capabilities.ScopeAdmin}}, nil
	}
	if IsLoopback(remoteAddr) {
		return AdminActor(), nil
	}
	return Actor{}, domainerr.Unauthorized("bearer token required")
}
