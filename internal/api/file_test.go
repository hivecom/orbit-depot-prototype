package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hivecom/orbit-depot/internal/auth"
	"github.com/hivecom/orbit-depot/internal/config"
	"github.com/hivecom/orbit-depot/internal/place"
	"github.com/hivecom/orbit-depot/internal/storage/fs"
	"github.com/hivecom/orbit-depot/internal/store/sqlite"
)

// fileServer builds a server with a real fs driver, a store, and a fixed
// identity, so file-deletion ownership can be exercised end to end.
func fileServer(t *testing.T, driver *fs.Driver, st *sqlite.Store, a auth.Authenticator) *Server {
	t.Helper()
	reg, err := place.New(map[string]place.Definition{"uploads": {}}, "uploads", 100<<20)
	if err != nil {
		t.Fatalf("place.New: %v", err)
	}
	cfg := &config.Config{Depot: config.Depot{Driver: "fs"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, log, Deps{Driver: driver, Auth: a, Places: reg, Store: st})
}

// uploadOne presigns and PUTs a small file as the server's identity, returning
// its object key.
func uploadOne(t *testing.T, s *Server) string {
	t.Helper()
	rec := postJSON(t, s, "/upload/presign", `{"filename":"f.png","size":5,"content_type":"image/png"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("presign = %d (%s)", rec.Code, rec.Body.String())
	}
	var pr presignResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &pr); err != nil {
		t.Fatalf("decode presign: %v", err)
	}
	put := httptest.NewRequest(http.MethodPut, pr.UploadURL, strings.NewReader("hello"))
	put.Header.Set("Content-Type", "image/png")
	prec := httptest.NewRecorder()
	s.Handler().ServeHTTP(prec, put)
	if prec.Code != http.StatusCreated {
		t.Fatalf("PUT = %d (%s)", prec.Code, prec.Body.String())
	}
	return pr.ObjectKey
}

func TestDeleteFileLifecycle(t *testing.T) {
	driver, err := fs.New(t.TempDir(), "http://depot.test")
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	st := keysStore(t)
	s := fileServer(t, driver, st, fixedAuth{oidcID("user-1")})

	key := uploadOne(t, s)
	if used, _ := st.Usage(context.Background(), "user-1", "iss"); used != 5 {
		t.Fatalf("usage before delete = %d, want 5", used)
	}

	// Delete it.
	if rec := do(t, s, http.MethodDelete, "/file/"+key); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204", rec.Code)
	}
	if used, _ := st.Usage(context.Background(), "user-1", "iss"); used != 0 {
		t.Errorf("usage after delete = %d, want 0", used)
	}
	// The bytes are gone from disk too.
	if rec := do(t, s, http.MethodGet, "/transfer/"+key); rec.Code != http.StatusNotFound {
		t.Errorf("GET deleted object = %d, want 404", rec.Code)
	}
	// Deleting again is a 404.
	if rec := do(t, s, http.MethodDelete, "/file/"+key); rec.Code != http.StatusNotFound {
		t.Errorf("second DELETE = %d, want 404", rec.Code)
	}
}

func TestDeleteFileOwnerIsolation(t *testing.T) {
	driver, err := fs.New(t.TempDir(), "http://depot.test")
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	st := keysStore(t)
	a := fileServer(t, driver, st, fixedAuth{oidcID("A")})
	b := fileServer(t, driver, st, fixedAuth{oidcID("B")})

	key := uploadOne(t, a)

	// B cannot delete A's file.
	if rec := do(t, b, http.MethodDelete, "/file/"+key); rec.Code != http.StatusNotFound {
		t.Errorf("B deleting A's file = %d, want 404", rec.Code)
	}
	if used, _ := st.Usage(context.Background(), "A", "iss"); used != 5 {
		t.Errorf("A's usage after B's attempt = %d, want 5", used)
	}
	// A still can.
	if rec := do(t, a, http.MethodDelete, "/file/"+key); rec.Code != http.StatusNoContent {
		t.Errorf("A deleting own file = %d, want 204", rec.Code)
	}
}

func TestDeleteFileRequiresIdentity(t *testing.T) {
	driver, err := fs.New(t.TempDir(), "http://depot.test")
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	s := fileServer(t, driver, keysStore(t), auth.Anonymous())
	if rec := do(t, s, http.MethodDelete, "/file/uploads/_anonymous/x/y.png"); rec.Code != http.StatusForbidden {
		t.Errorf("anonymous DELETE = %d, want 403", rec.Code)
	}
}
