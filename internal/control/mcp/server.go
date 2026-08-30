package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/buildinfo"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ProtocolVersion = "2026-07-28"
	DefaultPath     = "/mcp"
	MaxBodyBytes    = 1 << 20
	headerProtocol  = "Mcp-Protocol-Version"
)

type Server struct {
	app                *app.App
	allowLegacyClients bool
	sdk                *sdk.Server
	http               *sdk.StreamableHTTPHandler
}

func New(a *app.App, allowLegacy bool) (*Server, error) {
	info := buildinfo.Get()
	impl := &sdk.Implementation{Name: "labsso", Title: "LabSSO", Version: info.Version}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	sdkSrv := sdk.NewServer(impl, &sdk.ServerOptions{
		Instructions: "LabSSO control plane. Typed tools only. Protocol " + ProtocolVersion + ".",
		Logger:       logger,
		Capabilities: &sdk.ServerCapabilities{
			Tools:     &sdk.ToolCapabilities{ListChanged: false},
			Resources: &sdk.ResourceCapabilities{ListChanged: false, Subscribe: false},
		},
		SchemaCache: sdk.NewSchemaCache(),
	})
	s := &Server{app: a, allowLegacyClients: allowLegacy, sdk: sdkSrv}
	sdkSrv.AddReceivingMiddleware(s.pinProtocol)
	s.registerTools()
	s.registerResources()
	s.http = sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server {
		return s.sdk
	}, &sdk.StreamableHTTPOptions{
		Stateless:           true,
		Logger:              logger,
		MaxRequestBodyBytes: MaxBodyBytes,
	})
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if !auth.LoopbackHostAllowed(r.RemoteAddr, r.Host) {
		http.Error(w, "forbidden host", http.StatusForbidden)
		return
	}
	if r.Header.Get("Cookie") != "" {
		// Cookies are ignored for MCP auth; strip so they cannot become a session.
		r = r.Clone(r.Context())
		r.Header.Del("Cookie")
	}
	if !s.allowLegacyClients {
		if err := validateProtocolVersion(r); err != nil {
			writeRPC(w, http.StatusBadRequest, err)
			return
		}
	}
	actor, err := s.authenticate(r)
	if err != nil {
		writeRPC(w, http.StatusUnauthorized, err)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxActor{}, actor))
	s.http.ServeHTTP(w, r)
}

func (s *Server) authenticate(r *http.Request) (auth.Actor, error) {
	token := []byte(nil)
	if snap := s.app.Store().Load(); snap != nil {
		token = snap.AccessToken
	}
	return auth.Authenticate(r.RemoteAddr, r.Header.Get("Authorization"), token)
}

func (s *Server) pinProtocol(next sdk.MethodHandler) sdk.MethodHandler {
	return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
		if s.allowLegacyClients {
			return next(ctx, method, req)
		}
		if sr, ok := req.(interface{ ProtocolVersion() string }); ok {
			if v := sr.ProtocolVersion(); v != "" && v != ProtocolVersion {
				return nil, domainerr.Protocol("unsupported MCP protocol version " + v)
			}
		}
		return next(ctx, method, req)
	}
}

func validateProtocolVersion(r *http.Request) error {
	ver := strings.TrimSpace(r.Header.Get(headerProtocol))
	if ver == "" {
		return domainerr.Protocol("Mcp-Protocol-Version is required; only " + ProtocolVersion + " is supported")
	}
	if ver != ProtocolVersion {
		return domainerr.Protocol("unsupported MCP protocol version " + ver + "; only " + ProtocolVersion + " is supported")
	}
	return nil
}

type ctxActor struct{}

func actorFrom(ctx context.Context) auth.Actor {
	a, _ := ctx.Value(ctxActor{}).(auth.Actor)
	return a
}

func writeRPC(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"error": map[string]any{
			"code":    -32600,
			"message": err.Error(),
			"data":    map[string]any{"code": domainerr.CodeOf(err)},
		},
	})
}
