package fs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hivecom/orbit-depot/internal/storage"
)

const publicURL = "https://depot.example.com"

// newTestDriver builds an fs driver over a temp dir and a mux that mounts its
// transfer handlers exactly as the api package does.
func newTestDriver(t *testing.T) (*Driver, *http.ServeMux) {
	t.Helper()
	d, err := New(t.TempDir(), publicURL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("PUT /transfer/{key...}", d.UploadHandler())
	mux.Handle("GET /transfer/{key...}", d.DownloadHandler())
	return d, mux
}

// presignedPUT turns a presigned UploadTarget into a request the mux can route.
func presignedPUT(t *testing.T, target storage.UploadTarget, contentType, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(target.Method, target.URL, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

func TestPresignUploadRoundTrip(t *testing.T) {
	d, mux := newTestDriver(t)
	key := "uploads/abc/123-xyz/screenshot.png"
	body := "the bytes"

	target, err := d.PresignUpload(context.Background(), key, storage.Constraints{
		ContentType: "image/png",
		MaxSize:     1024,
		Expiry:      time.Minute,
	})
	if err != nil {
		t.Fatalf("PresignUpload: %v", err)
	}
	if !strings.HasPrefix(target.URL, publicURL+"/transfer/") {
		t.Errorf("upload URL = %q, want prefix %q/transfer/", target.URL, publicURL)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, presignedPUT(t, target, "image/png", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT = %d (%s), want 201", rec.Code, rec.Body.String())
	}

	// The bytes landed at the expected key on disk.
	got, err := os.ReadFile(filepath.Join(d.root, filepath.FromSlash(key)))
	if err != nil {
		t.Fatalf("read stored file: %v", err)
	}
	if string(got) != body {
		t.Errorf("stored content = %q, want %q", got, body)
	}

	// And it downloads back.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, publicURL+"/transfer/"+key, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200", rec.Code)
	}
	if rec.Body.String() != body {
		t.Errorf("downloaded content = %q, want %q", rec.Body.String(), body)
	}
}

func TestUploadRejectsTamperedSignature(t *testing.T) {
	d, mux := newTestDriver(t)
	target, _ := d.PresignUpload(context.Background(), "uploads/x/y/f.txt", storage.Constraints{MaxSize: 1024, Expiry: time.Minute})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, presignedPUT(t, target, "", "data"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("control PUT = %d, want 201", rec.Code)
	}

	// Flip the size param: the signature no longer matches the capability.
	tampered := target
	tampered.URL = strings.Replace(target.URL, "size=1024", "size=999999", 1)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, presignedPUT(t, tampered, "", "data"))
	if rec.Code != http.StatusForbidden {
		t.Errorf("tampered PUT = %d, want 403", rec.Code)
	}
}

func TestUploadRejectsExpired(t *testing.T) {
	d, mux := newTestDriver(t)
	target, _ := d.PresignUpload(context.Background(), "uploads/x/y/f.txt", storage.Constraints{
		MaxSize: 1024,
		Expiry:  -time.Second, // already expired
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, presignedPUT(t, target, "", "data"))
	if rec.Code != http.StatusGone {
		t.Errorf("expired PUT = %d, want 410", rec.Code)
	}
}

func TestUploadEnforcesContentType(t *testing.T) {
	d, mux := newTestDriver(t)
	target, _ := d.PresignUpload(context.Background(), "uploads/x/y/f.png", storage.Constraints{
		ContentType: "image/png",
		MaxSize:     1024,
		Expiry:      time.Minute,
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, presignedPUT(t, target, "text/plain", "data"))
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("content-type mismatch PUT = %d, want 415", rec.Code)
	}
}

func TestUploadEnforcesSize(t *testing.T) {
	d, mux := newTestDriver(t)
	target, _ := d.PresignUpload(context.Background(), "uploads/x/y/f.txt", storage.Constraints{
		MaxSize: 4,
		Expiry:  time.Minute,
	})

	// Body larger than the cap, sent without a truthful Content-Length so the
	// limit must be caught while streaming.
	req := httptest.NewRequest(target.Method, target.URL, strings.NewReader("way too many bytes"))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize PUT = %d, want 413", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(d.root, "uploads/x/y/f.txt")); !os.IsNotExist(err) {
		t.Error("oversize upload left a file on disk")
	}
}

func TestDownloadMissingIs404(t *testing.T) {
	_, mux := newTestDriver(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, publicURL+"/transfer/uploads/nope.txt", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET missing = %d, want 404", rec.Code)
	}
}

func TestKeyValidationRejectsTraversal(t *testing.T) {
	d, _ := newTestDriver(t)
	for _, key := range []string{"", "/etc/passwd", "uploads/../../etc/passwd", "a/./b", "a//b"} {
		if _, err := d.PresignUpload(context.Background(), key, storage.Constraints{Expiry: time.Minute}); err == nil {
			t.Errorf("PresignUpload(%q) = nil error, want rejection", key)
		}
	}
}

func TestResolveDownload(t *testing.T) {
	d, _ := newTestDriver(t)
	url, err := d.ResolveDownload(context.Background(), "uploads/a/b/c.png")
	if err != nil {
		t.Fatalf("ResolveDownload: %v", err)
	}
	if want := publicURL + "/transfer/uploads/a/b/c.png"; url != want {
		t.Errorf("ResolveDownload = %q, want %q", url, want)
	}
}
