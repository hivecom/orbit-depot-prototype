package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/hivecom/orbit-depot/internal/store"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "depot.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func upload(key, account, issuer string, size int64) store.Upload {
	return store.Upload{
		ObjectKey:        key,
		UploaderAccount:  account,
		UploaderIssuer:   issuer,
		FileSize:         size,
		ContentType:      "image/png",
		OriginalFilename: "f.png",
		UploadedAt:       time.Now(),
	}
}

func TestRecordAndUsage(t *testing.T) {
	s := open(t)

	mustRecord(t, s, upload("uploads/a/1/f.png", "sub-a", "iss", 100))
	mustRecord(t, s, upload("uploads/a/2/f.png", "sub-a", "iss", 250))
	mustRecord(t, s, upload("uploads/b/1/f.png", "sub-b", "iss", 999))

	if got := mustUsage(t, s, "sub-a", "iss"); got != 350 {
		t.Errorf("usage(sub-a) = %d, want 350", got)
	}
	if got := mustUsage(t, s, "sub-a", "other-iss"); got != 0 {
		t.Errorf("usage(sub-a, other issuer) = %d, want 0 (issuer-scoped)", got)
	}
	if got := mustUsage(t, s, "nobody", "iss"); got != 0 {
		t.Errorf("usage(nobody) = %d, want 0", got)
	}
}

func TestDeleteUpload(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	mustRecord(t, s, upload("uploads/a/1/f.png", "sub-a", "iss", 100))

	// Wrong owner cannot delete.
	if err := s.DeleteUpload(ctx, "uploads/a/1/f.png", "sub-b", "iss"); err != store.ErrNotFound {
		t.Errorf("delete by wrong owner = %v, want ErrNotFound", err)
	}
	if got := mustUsage(t, s, "sub-a", "iss"); got != 100 {
		t.Errorf("usage after failed delete = %d, want 100", got)
	}

	// Owner deletes.
	if err := s.DeleteUpload(ctx, "uploads/a/1/f.png", "sub-a", "iss"); err != nil {
		t.Fatalf("delete by owner: %v", err)
	}
	if got := mustUsage(t, s, "sub-a", "iss"); got != 0 {
		t.Errorf("usage after delete = %d, want 0", got)
	}
	// Deleting again is ErrNotFound.
	if err := s.DeleteUpload(ctx, "uploads/a/1/f.png", "sub-a", "iss"); err != store.ErrNotFound {
		t.Errorf("delete missing = %v, want ErrNotFound", err)
	}
}

func TestDeleteUploadAny(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	mustRecord(t, s, upload("uploads/a/1/f.png", "sub-a", "iss", 100))

	// Moderation delete ignores ownership.
	if err := s.DeleteUploadAny(ctx, "uploads/a/1/f.png"); err != nil {
		t.Fatalf("DeleteUploadAny: %v", err)
	}
	if got := mustUsage(t, s, "sub-a", "iss"); got != 0 {
		t.Errorf("usage after moderation delete = %d, want 0", got)
	}
	// Deleting again is ErrNotFound.
	if err := s.DeleteUploadAny(ctx, "uploads/a/1/f.png"); err != store.ErrNotFound {
		t.Errorf("delete missing = %v, want ErrNotFound", err)
	}
}

// listUpload builds a row with explicit content type, filename, and time so the
// listing tests can assert filtering and sorting deterministically.
func listUpload(key, account string, size int64, ctype, filename string, at time.Time) store.Upload {
	return store.Upload{
		ObjectKey:        key,
		UploaderAccount:  account,
		UploaderIssuer:   "iss",
		FileSize:         size,
		ContentType:      ctype,
		OriginalFilename: filename,
		UploadedAt:       at,
	}
}

func TestListUploads(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	t0 := time.Unix(1_700_000_000, 0).UTC()

	// Three rows for sub-a (varied time, size, type, name) and one for sub-b.
	mustRecord(t, s, listUpload("k1", "sub-a", 300, "image/png", "alpha.png", t0.Add(1*time.Hour)))
	mustRecord(t, s, listUpload("k2", "sub-a", 100, "image/png", "BRAVO.png", t0.Add(2*time.Hour)))
	mustRecord(t, s, listUpload("k3", "sub-a", 200, "text/plain", "charlie.txt", t0.Add(3*time.Hour)))
	mustRecord(t, s, listUpload("k4", "sub-b", 999, "image/png", "delta.png", t0.Add(4*time.Hour)))

	keys := func(us []store.Upload) []string {
		out := make([]string, len(us))
		for i, u := range us {
			out[i] = u.ObjectKey
		}
		return out
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	// Owner filter scopes to sub-a; default sort is uploaded_at desc.
	got, total, err := s.ListUploads(ctx, store.ListUploadsQuery{Account: "sub-a", Issuer: "iss", Limit: 50})
	if err != nil {
		t.Fatalf("ListUploads: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if want := []string{"k3", "k2", "k1"}; !eq(keys(got), want) {
		t.Errorf("default order = %v, want %v", keys(got), want)
	}

	// No owner filter (admin) sees every row.
	_, total, err = s.ListUploads(ctx, store.ListUploadsQuery{Limit: 50})
	if err != nil {
		t.Fatalf("ListUploads (admin): %v", err)
	}
	if total != 4 {
		t.Errorf("admin total = %d, want 4", total)
	}

	// Content-type filter.
	got, total, _ = s.ListUploads(ctx, store.ListUploadsQuery{Account: "sub-a", Issuer: "iss", ContentType: "image/png", Limit: 50})
	if total != 2 || !eq(keys(got), []string{"k2", "k1"}) {
		t.Errorf("content_type filter = %v (total %d), want [k2 k1] (2)", keys(got), total)
	}

	// Case-insensitive filename search.
	got, _, _ = s.ListUploads(ctx, store.ListUploadsQuery{Account: "sub-a", Issuer: "iss", Search: "bravo", Limit: 50})
	if !eq(keys(got), []string{"k2"}) {
		t.Errorf("search 'bravo' = %v, want [k2]", keys(got))
	}

	// Sort by file_size asc.
	got, _, _ = s.ListUploads(ctx, store.ListUploadsQuery{Account: "sub-a", Issuer: "iss", Sort: "file_size", Order: "asc", Limit: 50})
	if want := []string{"k2", "k3", "k1"}; !eq(keys(got), want) {
		t.Errorf("size asc = %v, want %v", keys(got), want)
	}

	// Paging: limit 2, offset 1 over the size-asc order.
	got, total, _ = s.ListUploads(ctx, store.ListUploadsQuery{Account: "sub-a", Issuer: "iss", Sort: "file_size", Order: "asc", Limit: 2, Offset: 1})
	if total != 3 || !eq(keys(got), []string{"k3", "k1"}) {
		t.Errorf("paged = %v (total %d), want [k3 k1] (3)", keys(got), total)
	}

	// Bad sort/order fall back to uploaded_at desc, never error.
	got, _, err = s.ListUploads(ctx, store.ListUploadsQuery{Account: "sub-a", Issuer: "iss", Sort: "drop table", Order: "sideways", Limit: 50})
	if err != nil {
		t.Fatalf("ListUploads bad sort: %v", err)
	}
	if want := []string{"k3", "k2", "k1"}; !eq(keys(got), want) {
		t.Errorf("bad sort fallback = %v, want %v", keys(got), want)
	}
}

func key(id, hash, owner string) store.APIKey {
	return store.APIKey{
		ID:           id,
		Hash:         hash,
		OwnerAccount: owner,
		OwnerIssuer:  "iss",
		Label:        "test key",
		Scopes:       []string{"upload"},
		CreatedAt:    time.Now(),
	}
}

func TestCreateResolveKey(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.CreateKey(ctx, key("id-1", "hash-1", "sub-a")); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	got, err := s.ResolveKey(ctx, "hash-1")
	if err != nil {
		t.Fatalf("ResolveKey: %v", err)
	}
	if got.ID != "id-1" || got.OwnerAccount != "sub-a" || got.Label != "test key" {
		t.Errorf("resolved key = %+v", got)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "upload" {
		t.Errorf("scopes = %v, want [upload]", got.Scopes)
	}

	if _, err := s.ResolveKey(ctx, "no-such-hash"); err != store.ErrNotFound {
		t.Errorf("resolve unknown = %v, want ErrNotFound", err)
	}
}

func TestListAndRevokeKey(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	mustCreate(t, s, key("id-1", "h1", "sub-a"))
	mustCreate(t, s, key("id-2", "h2", "sub-a"))
	mustCreate(t, s, key("id-3", "h3", "sub-b"))

	list, err := s.ListKeys(ctx, "sub-a", "iss")
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListKeys(sub-a) returned %d, want 2", len(list))
	}

	// Wrong owner cannot revoke.
	if err := s.RevokeKey(ctx, "id-1", "sub-b", "iss"); err != store.ErrNotFound {
		t.Errorf("revoke by wrong owner = %v, want ErrNotFound", err)
	}
	// Owner revokes; the key no longer resolves.
	if err := s.RevokeKey(ctx, "id-1", "sub-a", "iss"); err != nil {
		t.Fatalf("revoke by owner: %v", err)
	}
	if _, err := s.ResolveKey(ctx, "h1"); err != store.ErrNotFound {
		t.Errorf("resolve revoked key = %v, want ErrNotFound", err)
	}
}

func TestTouchKey(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	mustCreate(t, s, key("id-1", "h1", "sub-a"))

	before, _ := s.ResolveKey(ctx, "h1")
	if before.LastUsedAt != nil {
		t.Errorf("new key LastUsedAt = %v, want nil", before.LastUsedAt)
	}
	if err := s.TouchKey(ctx, "id-1"); err != nil {
		t.Fatalf("TouchKey: %v", err)
	}
	after, _ := s.ResolveKey(ctx, "h1")
	if after.LastUsedAt == nil {
		t.Error("LastUsedAt still nil after touch")
	}
}

func TestKeyExpiryRoundTrip(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	exp := time.Now().Add(24 * time.Hour).Truncate(time.Second).UTC()
	k := key("id-1", "h1", "sub-a")
	k.ExpiresAt = &exp
	mustCreate(t, s, k)

	got, _ := s.ResolveKey(ctx, "h1")
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, exp)
	}
}

func mustRecord(t *testing.T, s *Store, u store.Upload) {
	t.Helper()
	if err := s.RecordUpload(context.Background(), u); err != nil {
		t.Fatalf("RecordUpload: %v", err)
	}
}

func mustUsage(t *testing.T, s *Store, account, issuer string) int64 {
	t.Helper()
	n, err := s.Usage(context.Background(), account, issuer)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	return n
}

func mustCreate(t *testing.T, s *Store, k store.APIKey) {
	t.Helper()
	if err := s.CreateKey(context.Background(), k); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
}
