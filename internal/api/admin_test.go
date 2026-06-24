package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/hivecom/orbit-depot/internal/auth"
	"github.com/hivecom/orbit-depot/internal/store"
)

// adminID is an OIDC identity that matched the configured admin claim.
func adminID(sub string) *auth.Identity {
	return &auth.Identity{Subject: sub, Issuer: "iss", Method: auth.MethodOIDC, Admin: true}
}

func TestAdminListFilesSeesAllOwners(t *testing.T) {
	st := keysStore(t)
	recordFile(t, st, "uploads/u1/a", "user-1", "a.png")
	recordFile(t, st, "uploads/u2/b", "user-2", "b.png")

	resp := do(t, filesServer(st, adminID("admin-1")), http.MethodGet, "/admin/files")
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /admin/files = %d, want 200", resp.Code)
	}
	var got adminListFilesResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Total != 2 || len(got.Files) != 2 {
		t.Fatalf("got total=%d files=%d, want 2/2 (admin sees every owner)", got.Total, len(got.Files))
	}
	// The admin listing exposes the uploader identity the self listing hides.
	for _, f := range got.Files {
		if f.UploaderAccount == "" || f.UploaderIssuer == "" {
			t.Errorf("admin row missing uploader identity: %+v", f)
		}
	}
}

func TestAdminMetricsAggregates(t *testing.T) {
	st := keysStore(t)
	recordFile(t, st, "uploads/u1/a", "user-1", "a.png") // image, 100 bytes
	recordFile(t, st, "uploads/u1/b", "user-1", "b.png") // image, 100 bytes
	// A non-image upload so total_images differs from total_files.
	if err := st.RecordUpload(context.Background(), store.Upload{
		ObjectKey: "uploads/u2/c", UploaderAccount: "user-2", UploaderIssuer: "iss",
		FileSize: 50, ContentType: "application/pdf", OriginalFilename: "c.pdf", UploadedAt: time.Now(),
	}); err != nil {
		t.Fatalf("RecordUpload: %v", err)
	}

	resp := do(t, filesServer(st, adminID("admin-1")), http.MethodGet, "/admin/metrics")
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /admin/metrics = %d, want 200", resp.Code)
	}
	var got adminMetricsResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.TotalFiles != 3 || got.TotalSize != 250 || got.TotalImages != 2 {
		t.Fatalf("metrics = %+v, want files=3 size=250 images=2", got)
	}
}

func TestAdminMetricsScopesToUser(t *testing.T) {
	st := keysStore(t)
	recordFile(t, st, "uploads/u1/a", "user-1", "a.png")
	recordFile(t, st, "uploads/u2/b", "user-2", "b.png")

	resp := do(t, filesServer(st, adminID("admin-1")), http.MethodGet, "/admin/metrics?account=user-1")
	var got adminMetricsResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.TotalFiles != 1 || got.TotalImages != 1 {
		t.Fatalf("scoped metrics = %+v, want files=1 images=1 for user-1", got)
	}
}

func TestAdminMetricsRejectsNonAdmin(t *testing.T) {
	st := keysStore(t)
	resp := do(t, filesServer(st, oidcID("user-1")), http.MethodGet, "/admin/metrics")
	if resp.Code != http.StatusForbidden {
		t.Errorf("non-admin GET /admin/metrics = %d, want 403", resp.Code)
	}
}

func TestAdminListUploadersRanksByBytes(t *testing.T) {
	st := keysStore(t)
	// user-2 uploads more total bytes (recordFile is 100 each), so ranks first.
	recordFile(t, st, "uploads/u1/a", "user-1", "a.png")
	recordFile(t, st, "uploads/u2/b", "user-2", "b.png")
	recordFile(t, st, "uploads/u2/c", "user-2", "c.png")

	resp := do(t, filesServer(st, adminID("admin-1")), http.MethodGet, "/admin/users")
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /admin/users = %d, want 200", resp.Code)
	}
	var got adminListUploadersResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Total != 2 || len(got.Users) != 2 {
		t.Fatalf("got total=%d users=%d, want 2/2 distinct uploaders", got.Total, len(got.Users))
	}
	if got.Users[0].Account != "user-2" || got.Users[0].Files != 2 || got.Users[0].Bytes != 200 {
		t.Fatalf("top uploader = %+v, want user-2 with 2 files / 200 bytes", got.Users[0])
	}
	if got.Users[1].Account != "user-1" || got.Users[1].Files != 1 {
		t.Fatalf("second uploader = %+v, want user-1 with 1 file", got.Users[1])
	}
}

func TestAdminListUploadersRejectsNonAdmin(t *testing.T) {
	st := keysStore(t)
	resp := do(t, filesServer(st, oidcID("user-1")), http.MethodGet, "/admin/users")
	if resp.Code != http.StatusForbidden {
		t.Errorf("non-admin GET /admin/users = %d, want 403", resp.Code)
	}
}

func TestAdminListFilesFiltersByOwner(t *testing.T) {
	st := keysStore(t)
	recordFile(t, st, "uploads/u1/a", "user-1", "a.png")
	recordFile(t, st, "uploads/u2/b", "user-2", "b.png")

	resp := do(t, filesServer(st, adminID("admin-1")), http.MethodGet, "/admin/files?account=user-2")
	var got adminListFilesResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Total != 1 || len(got.Files) != 1 || got.Files[0].UploaderAccount != "user-2" {
		t.Fatalf("account filter gave total=%d, want only user-2's row", got.Total)
	}
}

func TestAdminListFilesRejectsNonAdmin(t *testing.T) {
	st := keysStore(t)
	recordFile(t, st, "uploads/u1/a", "user-1", "a.png")

	// A genuine OIDC login whose claim did not match the admin policy.
	resp := do(t, filesServer(st, oidcID("user-1")), http.MethodGet, "/admin/files")
	if resp.Code != http.StatusForbidden {
		t.Errorf("non-admin GET /admin/files = %d, want 403", resp.Code)
	}
}

func TestAdminListFilesRejectsAPIKey(t *testing.T) {
	st := keysStore(t)
	// Even an api_key flagged admin must be refused: admin is OIDC-only, so a
	// leaked key can never reach moderation.
	id := &auth.Identity{Subject: "bot", Issuer: "iss", Method: auth.MethodAPIKey, Admin: true}
	resp := do(t, filesServer(st, id), http.MethodGet, "/admin/files")
	if resp.Code != http.StatusForbidden {
		t.Errorf("api_key GET /admin/files = %d, want 403", resp.Code)
	}
}

func TestAdminListFilesRejectsAnonymous(t *testing.T) {
	st := keysStore(t)
	id := &auth.Identity{Method: auth.MethodAnonymous, Anonymous: true}
	resp := do(t, filesServer(st, id), http.MethodGet, "/admin/files")
	if resp.Code != http.StatusForbidden {
		t.Errorf("anonymous GET /admin/files = %d, want 403", resp.Code)
	}
}

func TestAdminDeletesAnyOwnersFile(t *testing.T) {
	st := keysStore(t)
	recordFile(t, st, "uploads/u2/c", "user-2", "c.png")

	// An admin deletes a file it does not own; the owner-scoped path would 404.
	resp := do(t, filesServer(st, adminID("admin-1")), http.MethodDelete, "/file/uploads/u2/c")
	if resp.Code != http.StatusNoContent {
		t.Fatalf("admin DELETE /file = %d, want 204", resp.Code)
	}
	// The row is gone.
	_, total, err := st.ListUploads(context.Background(), store.ListUploadsQuery{})
	if err != nil {
		t.Fatalf("ListUploads: %v", err)
	}
	if total != 0 {
		t.Errorf("after admin delete total=%d, want 0", total)
	}
}

func TestNonAdminCannotDeleteOthersFile(t *testing.T) {
	st := keysStore(t)
	recordFile(t, st, "uploads/u2/c", "user-2", "c.png")

	// A normal OIDC caller hitting someone else's key gets the owner-scoped 404.
	resp := do(t, filesServer(st, oidcID("user-1")), http.MethodDelete, "/file/uploads/u2/c")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("non-owner DELETE /file = %d, want 404", resp.Code)
	}
}
