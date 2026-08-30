package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/model"
)

const (
	MaxBodyBytes      = 1 << 20
	headerIdempotency = "Idempotency-Key"
	headerIfMatch     = "If-Match"
	headerExpected    = "X-LabSSO-Expected-Revision"
)

type Server struct {
	app      *app.App
	restPath string
}

func New(a *app.App, restPath string) *Server {
	if restPath == "" {
		restPath = "/v1"
	}
	return &Server{app: a, restPath: strings.TrimRight(restPath, "/")}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	p := s.restPath
	mux.HandleFunc("GET "+p+"/health/live", s.noAuth(s.live))
	mux.HandleFunc("GET "+p+"/health/ready", s.noAuth(s.ready))
	mux.HandleFunc("GET "+p+"/version", s.authed(s.version))
	mux.HandleFunc("GET "+p+"/capabilities", s.authed(s.capabilities))
	mux.HandleFunc("GET "+p+"/status", s.authed(s.status))
	mux.HandleFunc("GET "+p+"/schema/config", s.authed(s.schema))
	mux.HandleFunc("GET "+p+"/state", s.authed(s.state))
	mux.HandleFunc("POST "+p+"/state:validate", s.authed(s.validate))
	mux.HandleFunc("GET "+p+"/state:export", s.authed(s.export))
	mux.HandleFunc("POST "+p+"/state:reset", s.authed(s.reset))
	mux.HandleFunc("POST "+p+"/changes:plan", s.authed(s.plan))
	mux.HandleFunc("POST "+p+"/changes:apply", s.authed(s.apply))
	mux.HandleFunc("GET "+p+"/clients", s.authed(s.clients))
	mux.HandleFunc("GET "+p+"/clients/{id}", s.authed(s.clientGet))
	mux.HandleFunc("GET "+p+"/users", s.authed(s.users))
	mux.HandleFunc("GET "+p+"/users/{id}", s.authed(s.userGet))
	mux.HandleFunc("GET "+p+"/groups", s.authed(s.groups))
	mux.HandleFunc("GET "+p+"/groups/{id}", s.authed(s.groupGet))
	mux.HandleFunc("GET "+p+"/sessions", s.authed(s.sessions))
	mux.HandleFunc("POST "+p+"/sessions/", s.authed(s.sessionExpire))
	mux.HandleFunc("POST "+p+"/tunables/token:pause", s.authed(s.pauseToken))
	mux.HandleFunc("POST "+p+"/tunables/token:resume", s.authed(s.resumeToken))
	mux.HandleFunc("POST "+p+"/tunables/auth:force-fail", s.authed(s.forceFail))
	mux.HandleFunc("POST "+p+"/tunables/error:inject", s.authed(s.injectError))
	mux.HandleFunc("POST "+p+"/tunables/vendor:swap", s.authed(s.swapVendor))
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.LoopbackHostAllowed(r.RemoteAddr, r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		mux.ServeHTTP(w, r)
	})
	return http.NewCrossOriginProtection().Handler(inner)
}

func (s *Server) token() []byte {
	if snap := s.app.Store().Load(); snap != nil {
		return snap.AccessToken
	}
	return nil
}

func (s *Server) authenticate(r *http.Request) (auth.Actor, error) {
	return auth.Authenticate(r.RemoteAddr, r.Header.Get("Authorization"), s.token())
}

func (s *Server) noAuth(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return fn
}

func (s *Server) authed(fn func(http.ResponseWriter, *http.Request, auth.Actor)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, err := s.authenticate(r)
		if err != nil {
			writeError(w, err)
			return
		}
		fn(w, r, actor)
	}
}

func (s *Server) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.app.HealthLive())
}

func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	body, ok := s.app.HealthReady()
	code := http.StatusOK
	if !ok {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, body)
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request, actor auth.Actor) {
	info, err := s.app.Version(actor)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) capabilities(w http.ResponseWriter, _ *http.Request, actor auth.Actor) {
	caps, err := s.app.Capabilities(actor)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"capabilities": caps})
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request, actor auth.Actor) {
	st, err := s.app.GetStatus(actor)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) schema(w http.ResponseWriter, _ *http.Request, actor auth.Actor) {
	out, err := s.app.SchemaConfig(actor)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) state(w http.ResponseWriter, _ *http.Request, actor auth.Actor) {
	out, err := s.app.GetState(actor)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) export(w http.ResponseWriter, _ *http.Request, actor auth.Actor) {
	out, err := s.app.Export(actor)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out.YAML)
}

func (s *Server) validate(w http.ResponseWriter, r *http.Request, actor auth.Actor) {
	in, err := decodeChange(r)
	if err != nil {
		writeError(w, err)
		return
	}
	out, err := s.app.Validate(actor, app.ValidateIn{Operations: in.Operations})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) plan(w http.ResponseWriter, r *http.Request, actor auth.Actor) {
	in, err := decodeChange(r)
	if err != nil {
		writeError(w, err)
		return
	}
	out, err := s.app.Plan(actor, in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apply(w http.ResponseWriter, r *http.Request, actor auth.Actor) {
	in, err := decodeChange(r)
	if err != nil {
		writeError(w, err)
		return
	}
	out, err := s.app.Apply(actor, in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) reset(w http.ResponseWriter, r *http.Request, actor auth.Actor) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, err)
		return
	}
	out, err := s.app.Reset(actor, app.ResetIn{Reason: body.Reason})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) clients(w http.ResponseWriter, _ *http.Request, actor auth.Actor) {
	out, err := s.app.ListClients(actor)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) clientGet(w http.ResponseWriter, r *http.Request, actor auth.Actor) {
	out, err := s.app.GetClient(actor, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) users(w http.ResponseWriter, _ *http.Request, actor auth.Actor) {
	out, err := s.app.ListUsers(actor)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) userGet(w http.ResponseWriter, r *http.Request, actor auth.Actor) {
	out, err := s.app.GetUser(actor, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) groups(w http.ResponseWriter, _ *http.Request, actor auth.Actor) {
	out, err := s.app.ListGroups(actor)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) sessions(w http.ResponseWriter, _ *http.Request, actor auth.Actor) {
	out, err := s.app.ListSessions(actor)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) sessionExpire(w http.ResponseWriter, r *http.Request, actor auth.Actor) {
	if !strings.HasSuffix(r.URL.Path, ":expire") {
		writeError(w, domainerr.Validation("use POST /v1/sessions/{id}:expire"))
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, s.restPath+"/sessions/"), ":expire")
	if id == "" || id == r.URL.Path {
		writeError(w, domainerr.Validation("session id required"))
		return
	}
	if err := s.app.ExpireSession(actor, id); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) pauseToken(w http.ResponseWriter, _ *http.Request, actor auth.Actor) {
	if err := s.app.PauseToken(actor); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"paused": true})
}

func (s *Server) resumeToken(w http.ResponseWriter, _ *http.Request, actor auth.Actor) {
	if err := s.app.ResumeToken(actor); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"paused": false})
}

func (s *Server) forceFail(w http.ResponseWriter, r *http.Request, actor auth.Actor) {
	var body struct {
		On bool `json:"on"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, err)
		return
	}
	if err := s.app.ForceFail(actor, body.On); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"on": body.On})
}

func (s *Server) swapVendor(w http.ResponseWriter, r *http.Request, actor auth.Actor) {
	var body struct {
		Vendor           string  `json:"vendor"`
		TenantID         *string `json:"tenantId"`
		ExpectedRevision string  `json:"expectedRevision"`
		IdempotencyKey   string  `json:"idempotencyKey"`
		Reason           string  `json:"reason"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, err)
		return
	}
	expected := body.ExpectedRevision
	if expected == "" {
		expected = strings.Trim(r.Header.Get(headerIfMatch), `"`)
	}
	if expected == "" {
		expected = r.Header.Get(headerExpected)
	}
	key := body.IdempotencyKey
	if key == "" {
		key = r.Header.Get(headerIdempotency)
	}
	out, err := s.app.SwapVendor(actor, app.SwapVendorIn{
		Vendor:           body.Vendor,
		TenantID:         body.TenantID,
		ExpectedRevision: expected,
		IdempotencyKey:   key,
		Reason:           body.Reason,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) injectError(w http.ResponseWriter, r *http.Request, actor auth.Actor) {
	var body struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, err)
		return
	}
	if err := s.app.InjectError(actor, body.Code); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": body.Code})
}

func (s *Server) groupGet(w http.ResponseWriter, r *http.Request, actor auth.Actor) {
	out, err := s.app.GetGroup(actor, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type changeBody struct {
	ExpectedRevision string            `json:"expectedRevision"`
	IdempotencyKey   string            `json:"idempotencyKey"`
	Reason           string            `json:"reason"`
	Operations       []model.Operation `json:"operations"`
}

func decodeChange(r *http.Request) (app.ChangeIn, error) {
	var body changeBody
	if err := decodeJSON(r, &body); err != nil {
		return app.ChangeIn{}, err
	}
	expected := body.ExpectedRevision
	if expected == "" {
		expected = strings.Trim(r.Header.Get(headerIfMatch), `"`)
	}
	if expected == "" {
		expected = r.Header.Get(headerExpected)
	}
	key := body.IdempotencyKey
	if key == "" {
		key = r.Header.Get(headerIdempotency)
	}
	return app.ChangeIn{
		ExpectedRevision: expected,
		IdempotencyKey:   key,
		Reason:           body.Reason,
		Operations:       body.Operations,
	}, nil
}

func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, MaxBodyBytes))
	if err := dec.Decode(dst); err != nil && err != io.EOF {
		if err.Error() == "http: request body too large" {
			return domainerr.Validation("request body exceeds 1 MiB")
		}
		return domainerr.Validation("invalid JSON: " + err.Error())
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	dcode := "internal"
	msg := err.Error()
	if e := domainerr.CodeOf(err); e != "" {
		dcode = e
		switch e {
		case domainerr.CodeRevisionConflict, domainerr.CodeConflict:
			code = http.StatusConflict
		case domainerr.CodeValidation:
			code = http.StatusBadRequest
		case domainerr.CodeNotFound:
			code = http.StatusNotFound
		case domainerr.CodeUnauthorized:
			code = http.StatusUnauthorized
		case domainerr.CodeForbidden:
			code = http.StatusForbidden
		}
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "urn:labsso:error:" + strings.ReplaceAll(dcode, "_", "-"),
		"title":  dcode,
		"status": code,
		"code":   dcode,
		"detail": msg,
	})
}
