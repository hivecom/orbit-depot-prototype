package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hivecom/orbit-depot/internal/auth"
	"github.com/hivecom/orbit-depot/internal/config"
	"github.com/hivecom/orbit-depot/internal/place"
	"github.com/hivecom/orbit-depot/internal/quota"
	"github.com/hivecom/orbit-depot/internal/storage/fs"
	"github.com/hivecom/orbit-depot/internal/store/sqlite"
)

// multipartUpload posts a one-shot upload with a single file part (and an
// optional place field), the shape a cURL/ShareX client sends.
func multipartUpload(t *testing.T, s *Server, place, filename, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if place != "" {
		if err := mw.WriteField("place", place); err != nil {
			t.Fatal(err)
		}
	}
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, filename))
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	fw, err := mw.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// fixedAuth resolves every request to the same identified caller, so the presign
// path exercises the quota and recording branches that anonymous skips.
type fixedAuth struct{ id *auth.Identity }

func (f fixedAuth) Authenticate(*http.Request) (*auth.Identity, error) { return f.id, nil }

// uploadServer builds a server with the fs driver, anonymous auth, and a place
// registry - the anonymous + fs vertical slice. The same server mounts both the
// presign endpoint and the fs transfer routes, so a test can drive the whole
// loop through one handler.
func uploadServer(t *testing.T, globalMax int64) *Server {
	t.Helper()
	driver, err := fs.New(t.TempDir(), "http://depot.test")
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	reg, err := place.New(map[string]place.Definition{"uploads": {}}, "uploads", globalMax)
	if err != nil {
		t.Fatalf("place.New: %v", err)
	}
	cfg := &config.Config{Depot: config.Depot{Driver: "fs"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, log, Deps{Driver: driver, Auth: auth.Anonymous(), Places: reg})
}

func postJSON(t *testing.T, s *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestPresignAnonymousFullLoop(t *testing.T) {
	s := uploadServer(t, 100<<20)

	rec := postJSON(t, s, "/upload/presign", `{"filename":"shot.png","size":9,"content_type":"image/png"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("presign = %d (%s), want 200", rec.Code, rec.Body.String())
	}

	var pr presignResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &pr); err != nil {
		t.Fatalf("decode presign response: %v", err)
	}
	if !strings.HasPrefix(pr.ObjectKey, "uploads/_anonymous/") {
		t.Errorf("object_key = %q, want uploads/_anonymous/ prefix", pr.ObjectKey)
	}
	if pr.Method != http.MethodPut || pr.UploadURL == "" || pr.DownloadURL == "" {
		t.Fatalf("presign response = %+v", pr)
	}

	// PUT the bytes to the presigned URL, through the same server.
	body := "the bytes"
	put := httptest.NewRequest(http.MethodPut, pr.UploadURL, strings.NewReader(body))
	put.Header.Set("Content-Type", "image/png")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, put)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT = %d (%s), want 201", rec.Code, rec.Body.String())
	}

	// GET it back from the download URL.
	get := httptest.NewRequest(http.MethodGet, pr.DownloadURL, nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, get)
	if rec.Code != http.StatusOK || rec.Body.String() != body {
		t.Fatalf("GET = %d, body = %q, want 200 and %q", rec.Code, rec.Body.String(), body)
	}
}

func TestPresignRejectsOversize(t *testing.T) {
	s := uploadServer(t, 4) // 4-byte global cap
	rec := postJSON(t, s, "/upload/presign", `{"filename":"big.bin","size":1000,"content_type":"application/octet-stream"}`)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize presign = %d, want 413", rec.Code)
	}
}

func TestPresignUnknownPlace(t *testing.T) {
	s := uploadServer(t, 100<<20)
	rec := postJSON(t, s, "/upload/presign", `{"filename":"f.txt","size":10,"place":"nope"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown place = %d, want 404", rec.Code)
	}
}

func TestPresignRequiresFilename(t *testing.T) {
	s := uploadServer(t, 100<<20)
	rec := postJSON(t, s, "/upload/presign", `{"size":10}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing filename = %d, want 400", rec.Code)
	}
}

// With no default place configured, a request that omits "place" is rejected.
func TestPresignNoPlaceNoDefault(t *testing.T) {
	driver, err := fs.New(t.TempDir(), "http://depot.test")
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	reg, err := place.New(map[string]place.Definition{"uploads": {}}, "", 100<<20) // no default
	if err != nil {
		t.Fatalf("place.New: %v", err)
	}
	cfg := &config.Config{Depot: config.Depot{Driver: "fs"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(cfg, log, Deps{Driver: driver, Auth: auth.Anonymous(), Places: reg})

	rec := postJSON(t, s, "/upload/presign", `{"filename":"f.txt","size":10}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("omitted place with no default = %d, want 400", rec.Code)
	}
	// Naming the place explicitly still works.
	rec = postJSON(t, s, "/upload/presign", `{"filename":"f.txt","size":10,"place":"uploads"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("explicit place = %d, want 200", rec.Code)
	}
}

// With an identity, a store, and a real quota enforcer, a presign records the
// upload row and counts against the user's quota; a request that would exceed it
// is rejected before any URL is issued.
func TestPresignRecordsAndEnforcesQuota(t *testing.T) {
	driver, err := fs.New(t.TempDir(), "http://depot.test")
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	reg, err := place.New(map[string]place.Definition{"uploads": {}}, "uploads", 100<<20)
	if err != nil {
		t.Fatalf("place.New: %v", err)
	}
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "depot.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	id := &auth.Identity{Subject: "user-123", Issuer: "iss"}
	cfg := &config.Config{Depot: config.Depot{Driver: "fs"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(cfg, log, Deps{
		Driver: driver,
		Auth:   fixedAuth{id},
		Places: reg,
		Store:  st,
		Quota:  quota.New(st, 20, nil), // 20-byte per-user limit
	})

	// First upload (10 bytes) fits and is recorded.
	if rec := postJSON(t, s, "/upload/presign", `{"filename":"a.bin","size":10,"content_type":"application/octet-stream"}`); rec.Code != http.StatusOK {
		t.Fatalf("first presign = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if used, err := st.Usage(context.Background(), "user-123", "iss"); err != nil || used != 10 {
		t.Fatalf("usage after first presign = %d, %v; want 10, nil", used, err)
	}

	// Second upload (15 bytes) would total 25 > 20: rejected as over quota.
	if rec := postJSON(t, s, "/upload/presign", `{"filename":"b.bin","size":15,"content_type":"application/octet-stream"}`); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-quota presign = %d, want 413", rec.Code)
	}
	// The rejected upload left no row behind.
	if used, _ := st.Usage(context.Background(), "user-123", "iss"); used != 10 {
		t.Fatalf("usage after rejected presign = %d, want 10 (no row written)", used)
	}
}

// The CLI/API-key path: one-shot multipart upload, then fetch it back.
func TestOneshotUploadFullLoop(t *testing.T) {
	s := uploadServer(t, 100<<20)

	rec := multipartUpload(t, s, "", "shot.png", "image/png", "the bytes")
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /upload = %d (%s), want 201", rec.Code, rec.Body.String())
	}
	var resp oneshotResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.HasPrefix(resp.ObjectKey, "uploads/_anonymous/") || resp.Size != 9 || resp.URL == "" {
		t.Fatalf("response = %+v", resp)
	}

	// The returned URL serves the stored bytes.
	get := httptest.NewRequest(http.MethodGet, resp.URL, nil)
	grec := httptest.NewRecorder()
	s.Handler().ServeHTTP(grec, get)
	if grec.Code != http.StatusOK || grec.Body.String() != "the bytes" {
		t.Fatalf("GET = %d, body = %q, want 200 and the bytes", grec.Code, grec.Body.String())
	}
}

func TestOneshotRecordsAndEnforcesQuota(t *testing.T) {
	driver, err := fs.New(t.TempDir(), "http://depot.test")
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	reg, err := place.New(map[string]place.Definition{"uploads": {}}, "uploads", 100<<20)
	if err != nil {
		t.Fatalf("place.New: %v", err)
	}
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "depot.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	id := &auth.Identity{Subject: "user-1", Issuer: "iss", Method: auth.MethodAPIKey}
	cfg := &config.Config{Depot: config.Depot{Driver: "fs"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(cfg, log, Deps{Driver: driver, Auth: fixedAuth{id}, Places: reg, Store: st, Quota: quota.New(st, 20, nil)})

	if rec := multipartUpload(t, s, "", "a.bin", "application/octet-stream", "0123456789"); rec.Code != http.StatusCreated {
		t.Fatalf("first upload = %d (%s), want 201", rec.Code, rec.Body.String())
	}
	if used, err := st.Usage(context.Background(), "user-1", "iss"); err != nil || used != 10 {
		t.Fatalf("usage = %d, %v; want 10, nil", used, err)
	}
	// 15 more would total 25 > 20.
	if rec := multipartUpload(t, s, "", "b.bin", "application/octet-stream", "0123456789abcde"); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-quota upload = %d, want 413", rec.Code)
	}
	if used, _ := st.Usage(context.Background(), "user-1", "iss"); used != 10 {
		t.Fatalf("usage after rejected upload = %d, want 10", used)
	}
}

func TestOneshotOversizeAndMissingFile(t *testing.T) {
	s := uploadServer(t, 4) // 4-byte place cap

	if rec := multipartUpload(t, s, "", "big.bin", "application/octet-stream", "way too big"); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize one-shot = %d, want 413", rec.Code)
	}

	// A multipart body with no "file" part is a bad request.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("place", "uploads")
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing file part = %d, want 400", rec.Code)
	}
}

func TestPresignNotImplementedWithoutDeps(t *testing.T) {
	cfg := &config.Config{Depot: config.Depot{Driver: "fs"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(cfg, log, Deps{}) // no driver/auth/places
	rec := postJSON(t, s, "/upload/presign", `{"filename":"f.txt","size":10}`)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("no-deps presign = %d, want 501", rec.Code)
	}
}
