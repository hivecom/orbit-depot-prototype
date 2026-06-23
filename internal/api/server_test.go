package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hivecom/orbit-depot/internal/config"
	"github.com/hivecom/orbit-depot/internal/storage"
)

func testServer(t *testing.T, deps Deps) *Server {
	t.Helper()
	cfg := &config.Config{Depot: config.Depot{Driver: "fs"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, log, deps)
}

func do(t *testing.T, s *Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestHealth(t *testing.T) {
	rec := do(t, testServer(t, Deps{}), http.MethodGet, "/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"status":"ok"`) || !strings.Contains(body, `"driver":"fs"`) {
		t.Errorf("GET /health body = %q", body)
	}
}

func TestStubsReturn501(t *testing.T) {
	s := testServer(t, Deps{})
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/upload/presign"},
		{http.MethodPost, "/upload"},
		{http.MethodPost, "/keys"},
		{http.MethodGet, "/keys"},
		{http.MethodDelete, "/keys/abc"},
		{http.MethodGet, "/files"},
		{http.MethodDelete, "/file/uploads/x/y.png"},
		{http.MethodGet, "/quota"},
	} {
		if rec := do(t, s, tc.method, tc.path); rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s = %d, want 501", tc.method, tc.path, rec.Code)
		}
	}
}

// The proxied transfer routes must mount only when the active driver moves
// bytes through Depot itself (a ProxyDriver). A plain driver or no driver must
// leave those routes unrouted (404).
func TestProxyRoutesMountForProxyDriverOnly(t *testing.T) {
	cases := map[string]struct {
		driver storage.Driver
		want   int
	}{
		"proxy driver mounts transfer routes": {fakeProxyDriver{}, http.StatusTeapot},
		"plain driver does not":               {fakePlainDriver{}, http.StatusNotFound},
		"no driver does not":                  {nil, http.StatusNotFound},
	}
	for name, tc := range cases {
		s := testServer(t, Deps{Driver: tc.driver})
		if rec := do(t, s, http.MethodGet, "/transfer/uploads/x"); rec.Code != tc.want {
			t.Errorf("%s: GET /transfer = %d, want %d", name, rec.Code, tc.want)
		}
	}
}

// fakePlainDriver implements storage.Driver only.
type fakePlainDriver struct{}

func (fakePlainDriver) PresignUpload(context.Context, string, storage.Constraints) (storage.UploadTarget, error) {
	return storage.UploadTarget{}, nil
}
func (fakePlainDriver) ResolveDownload(context.Context, string) (string, error) { return "", nil }
func (fakePlainDriver) DeleteObject(context.Context, string) error              { return nil }

// fakeProxyDriver additionally implements storage.ProxyDriver; its handlers
// answer with a recognizable status so the test can confirm they were mounted.
type fakeProxyDriver struct{ fakePlainDriver }

func (fakeProxyDriver) UploadHandler() http.Handler   { return teapot() }
func (fakeProxyDriver) DownloadHandler() http.Handler { return teapot() }

func teapot() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
}
