package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hivecom/orbit-depot/internal/config"
)

func corsServer(t *testing.T, origins []string) *Server {
	t.Helper()
	cfg := &config.Config{Depot: config.Depot{Driver: "fs", CORSOrigins: origins}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, log, Deps{})
}

func reqWithOrigin(method, path, origin string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func serve(s *Server, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, r)
	return rec
}

func TestCORSPreflightAllowedOrigin(t *testing.T) {
	s := corsServer(t, []string{"https://hivecom.com"})

	rec := serve(s, reqWithOrigin(http.MethodOptions, "/upload/presign", "https://hivecom.com"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://hivecom.com" {
		t.Errorf("Allow-Origin = %q, want the echoed origin", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("preflight missing Access-Control-Allow-Headers")
	}
}

func TestCORSActualRequestGetsHeader(t *testing.T) {
	s := corsServer(t, []string{"https://hivecom.com"})

	rec := serve(s, reqWithOrigin(http.MethodGet, "/health", "https://hivecom.com"))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://hivecom.com" {
		t.Errorf("Allow-Origin = %q, want the echoed origin", got)
	}
}

func TestCORSDisallowedOriginGetsNoHeader(t *testing.T) {
	s := corsServer(t, []string{"https://hivecom.com"})

	rec := serve(s, reqWithOrigin(http.MethodGet, "/health", "https://evil.example.com"))
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty for a disallowed origin", got)
	}
}

func TestCORSWildcard(t *testing.T) {
	s := corsServer(t, []string{"*"})

	rec := serve(s, reqWithOrigin(http.MethodGet, "/health", "https://anything.example"))
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin = %q, want *", got)
	}
}

func TestCORSDisabledByDefault(t *testing.T) {
	s := corsServer(t, nil)

	rec := serve(s, reqWithOrigin(http.MethodGet, "/health", "https://hivecom.com"))
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty when CORS is unconfigured", got)
	}
	// And a stray OPTIONS is not hijacked into a 204 when CORS is off.
	if rec := serve(s, reqWithOrigin(http.MethodOptions, "/health", "")); rec.Code == http.StatusNoContent {
		t.Error("OPTIONS returned 204 with CORS disabled; should fall through to the mux")
	}
}
