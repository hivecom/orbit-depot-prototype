// Package api wires Depot's HTTP surface. The Server holds the seams (driver,
// authenticator, store, limiter) and routes requests to handlers. Step 1 boots
// with only the route surface and a working health check; each handler is
// filled in as its capability lands.
package api

import (
	"log/slog"
	"net/http"

	"github.com/hivecom/orbit-depot/internal/auth"
	"github.com/hivecom/orbit-depot/internal/config"
	"github.com/hivecom/orbit-depot/internal/quota"
	"github.com/hivecom/orbit-depot/internal/ratelimit"
	"github.com/hivecom/orbit-depot/internal/storage"
	"github.com/hivecom/orbit-depot/internal/store"
)

// Server holds Depot's runtime dependencies and HTTP routing.
type Server struct {
	cfg     *config.Config
	log     *slog.Logger
	driver  storage.Driver
	auth    auth.Authenticator
	store   store.Store // nil when no stateful capability is enabled
	limiter ratelimit.Limiter
	quota   quota.Enforcer
	mux     *http.ServeMux
}

// Deps are the seams a Server runs against. Any of the seam fields may be left
// for the zero value during early bring-up; routes that need a missing seam
// report that they are not yet implemented.
type Deps struct {
	Driver  storage.Driver
	Auth    auth.Authenticator
	Store   store.Store
	Limiter ratelimit.Limiter
	Quota   quota.Enforcer
}

// New builds a Server and registers its routes.
func New(cfg *config.Config, log *slog.Logger, deps Deps) *Server {
	s := &Server{
		cfg:     cfg,
		log:     log,
		driver:  deps.Driver,
		auth:    deps.Auth,
		store:   deps.Store,
		limiter: deps.Limiter,
		quota:   deps.Quota,
		mux:     http.NewServeMux(),
	}
	if s.quota == nil {
		s.quota = quota.Allow
	}
	s.routes()
	return s
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	// Operational.
	s.mux.HandleFunc("GET /health", s.handleHealth)

	// Upload.
	s.mux.HandleFunc("POST /upload/presign", s.notImplemented("presign"))
	s.mux.HandleFunc("POST /upload", s.notImplemented("one-shot upload"))

	// API keys (require oidc).
	s.mux.HandleFunc("POST /keys", s.notImplemented("mint key"))
	s.mux.HandleFunc("GET /keys", s.notImplemented("list keys"))
	s.mux.HandleFunc("DELETE /keys/{id}", s.notImplemented("revoke key"))

	// Files.
	s.mux.HandleFunc("DELETE /file/{key...}", s.notImplemented("delete file"))

	// Quota (carved out; enforcement deferred).
	s.mux.HandleFunc("GET /quota", s.notImplemented("quota"))

	// Proxied transfer routes are mounted only when the active driver moves
	// bytes through Depot itself (the fs driver).
	if pd, ok := s.driver.(storage.ProxyDriver); ok {
		s.mux.Handle("PUT /transfer/{key...}", pd.UploadHandler())
		s.mux.Handle("GET /transfer/{key...}", pd.DownloadHandler())
	}
}

// notImplemented returns a handler that reports a not-yet-built capability. It
// keeps the full API surface visible and routable during bring-up.
func (s *Server) notImplemented(what string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotImplemented, what+" is not implemented yet")
	}
}
