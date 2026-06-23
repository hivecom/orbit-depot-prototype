package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/hivecom/orbit-depot/internal/auth"
	"github.com/hivecom/orbit-depot/internal/config"
	"github.com/hivecom/orbit-depot/internal/store"
	"github.com/hivecom/orbit-depot/internal/store/sqlite"
)

// urlDriver resolves a deterministic download URL from the key so the listing
// test can assert the handler builds url through the driver.
type urlDriver struct{ fakePlainDriver }

func (urlDriver) ResolveDownload(_ context.Context, key string) (string, error) {
	return "https://depot.example/" + key, nil
}

func filesServer(st *sqlite.Store, id *auth.Identity) *Server {
	cfg := &config.Config{Depot: config.Depot{Driver: "fs"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, log, Deps{Auth: fixedAuth{id}, Store: st, Driver: urlDriver{}})
}

func recordFile(t *testing.T, st *sqlite.Store, key, account, name string) {
	t.Helper()
	err := st.RecordUpload(context.Background(), store.Upload{
		ObjectKey:        key,
		UploaderAccount:  account,
		UploaderIssuer:   "iss",
		FileSize:         100,
		ContentType:      "image/png",
		OriginalFilename: name,
		UploadedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("RecordUpload: %v", err)
	}
}

func TestListFilesScopesToCaller(t *testing.T) {
	st := keysStore(t)
	recordFile(t, st, "uploads/u1/a", "user-1", "a.png")
	recordFile(t, st, "uploads/u1/b", "user-1", "b.png")
	recordFile(t, st, "uploads/u2/c", "user-2", "c.png")

	resp := do(t, filesServer(st, oidcID("user-1")), http.MethodGet, "/files")
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /files = %d, want 200", resp.Code)
	}
	var got listFilesResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Total != 2 || len(got.Files) != 2 {
		t.Fatalf("got total=%d files=%d, want 2/2 (caller-scoped, never user-2's row)", got.Total, len(got.Files))
	}
	for _, f := range got.Files {
		if f.URL != "https://depot.example/"+f.ObjectKey {
			t.Errorf("url = %q, want built from object_key via the driver", f.URL)
		}
	}
}

func TestListFilesAppliesLimit(t *testing.T) {
	st := keysStore(t)
	for i := 0; i < 5; i++ {
		recordFile(t, st, "k"+strconv.Itoa(i), "u", "f.png")
	}

	resp := do(t, filesServer(st, oidcID("u")), http.MethodGet, "/files?limit=2")
	var got listFilesResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Files) != 2 || got.Total != 5 {
		t.Errorf("limit=2 gave files=%d total=%d, want 2 files and total 5", len(got.Files), got.Total)
	}
}

func TestListFilesRejectsBadParams(t *testing.T) {
	st := keysStore(t)
	recordFile(t, st, "k", "u", "f.png")
	s := filesServer(st, oidcID("u"))

	for _, path := range []string{
		"/files?sort=bogus",
		"/files?order=sideways",
		"/files?limit=abc",
		"/files?offset=xyz",
	} {
		if resp := do(t, s, http.MethodGet, path); resp.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400", path, resp.Code)
		}
	}

	// An over-max limit is clamped, not rejected: it is a valid integer and the
	// cap is documented behavior.
	if resp := do(t, s, http.MethodGet, "/files?limit=500"); resp.Code != http.StatusOK {
		t.Errorf("GET /files?limit=500 = %d, want 200 (clamped, not rejected)", resp.Code)
	}
}

func TestListFilesRejectsAnonymous(t *testing.T) {
	st := keysStore(t)
	cfg := &config.Config{Depot: config.Depot{Driver: "fs"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(cfg, log, Deps{Auth: auth.Anonymous(), Store: st, Driver: urlDriver{}})

	if resp := do(t, s, http.MethodGet, "/files"); resp.Code != http.StatusForbidden {
		t.Errorf("anonymous GET /files = %d, want 403", resp.Code)
	}
}
