package app

import (
	"net/http"
	"sync"

	"github.com/hilather/go-lab-sso/internal/audit"
	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/loginui"
	"github.com/hilather/go-lab-sso/internal/oidc"
	"github.com/hilather/go-lab-sso/internal/saml"
	"github.com/hilather/go-lab-sso/internal/snapshot"
	"github.com/hilather/go-lab-sso/internal/wsfed"
)

type App struct {
	mu            sync.Mutex
	store         *snapshot.Store
	bootstrapPath string
	baseDir       string
	env           compiler.Env
	idemp         *idempCache
	audit         *audit.Ring
	requireHTTPS  bool
	httpsBound    bool
	httpsHandler  http.Handler
	oidc          *oidc.Provider
	saml          *saml.Provider
	opsess        opStore
}

type Options struct {
	Store         *snapshot.Store
	BootstrapPath string
	BaseDir       string
	Env           compiler.Env
	Audit         *audit.Ring
}

func New(opt Options) *App {
	st := opt.Store
	if st == nil {
		st = snapshot.NewStore()
	}
	ring := opt.Audit
	if ring == nil {
		ring = audit.NewRing(256)
	}
	prov := oidc.New(st)
	prov.SetWarn(func(msg string) {
		ring.Emit(audit.Event{Capability: "sso.oidc.overage", Reason: msg, Result: audit.ResultOK})
	})
	samlProv := saml.New(st, prov.Runtime())
	wsfedProv := wsfed.New(st, prov.Runtime())
	mux := http.NewServeMux()
	mux.Handle("/", prov.Handler())
	samlProv.Mount(mux)
	wsfedProv.Mount(mux)
	loginui.New(st, prov, samlProv, wsfedProv, opt.BaseDir).Mount(mux)
	return &App{
		store:         st,
		bootstrapPath: opt.BootstrapPath,
		baseDir:       opt.BaseDir,
		env:           opt.Env,
		idemp:         newIdemp(256),
		audit:         ring,
		oidc:          prov,
		saml:          samlProv,
		httpsHandler:  mux,
	}
}

func (a *App) OIDC() *oidc.Provider { return a.oidc }

func (a *App) Store() *snapshot.Store { return a.store }

func (a *App) Audit() *audit.Ring { return a.audit }

func (a *App) SetHTTPSHandler(h http.Handler) { a.httpsHandler = h }

func (a *App) HTTPSHandler() http.Handler {
	if a.httpsHandler != nil {
		return a.httpsHandler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
}

func (a *App) compileOpts(gen int, bootRev string) compiler.Options {
	return compiler.Options{
		Env:               a.env,
		BaseDir:           a.baseDir,
		Generation:        gen,
		BootstrapRevision: bootRev,
	}
}
