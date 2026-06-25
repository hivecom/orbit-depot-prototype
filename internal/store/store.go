// Package store defines the third seam: durable metadata. The store records
// uploads (for quota accounting, deletion, and audit) and manages API keys. It
// is only consulted when a stateful capability is enabled; a pure-anonymous
// Depot runs with no store at all (a nil Store).
//
// The store is the system of record. Redis, when present, is only a
// coordination layer in front of it, never a replacement for it.
package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a lookup (object key, API key) has no match.
var ErrNotFound = errors.New("not found")

// Upload is the metadata row written at presign time. The presigned URL
// constrains the actual upload, so the row is a reliable record of intent even
// before the bytes land. Orphaned rows (client never completed) are reconciled
// by a periodic cleanup job.
type Upload struct {
	ObjectKey        string
	UploaderAccount  string // from the JWT sub, or the API key owner
	UploaderIssuer   string // from the JWT iss; supports multi-server identity
	FileSize         int64
	ContentType      string
	OriginalFilename string
	UploadedAt       time.Time
	// AllowedRecipients is reserved for recipient-scoped DM uploads (NEXT).
	// AllowedRecipients []string
}

// ListUploadsQuery filters and pages a listing of uploads. The self listing
// (GET /files) forces Account/Issuer to the caller; the admin listing
// (GET /admin/files) leaves Account empty for no owner filter and may set the
// extra ContentType filter. Sort and Order are whitelisted by the store, never
// interpolated raw.
type ListUploadsQuery struct {
	Account, Issuer     string // empty Account = no owner filter (admin only)
	ContentType, Search string
	Sort                string // "uploaded_at" | "file_size"
	Order               string // "asc" | "desc"
	Limit, Offset       int
}

// Allowed sort and order values for ListUploadsQuery. The HTTP layer validates
// input against these; the SQL store whitelists the same set as an injection
// backstop. An empty value means "use the default" (uploaded_at, desc).
var (
	validSorts  = map[string]bool{"uploaded_at": true, "file_size": true}
	validOrders = map[string]bool{"asc": true, "desc": true}
)

// ValidSort reports whether s is an accepted ListUploadsQuery sort value.
func ValidSort(s string) bool { return validSorts[s] }

// ValidOrder reports whether o is an accepted ListUploadsQuery order value.
func ValidOrder(o string) bool { return validOrders[o] }

// UploaderUsage is one uploader's aggregate footprint, for the admin per-user
// leaderboard. Account is the raw OIDC subject (the upload owner), not a
// username; the client resolves it. Files is the uploader's total upload count.
type UploaderUsage struct {
	Account, Issuer string
	Files           int
	Bytes           int64
}

// ListUploadersQuery pages and sorts the uploader leaderboard. Unlike
// ListUploadsQuery it sorts on aggregates: file_count (the upload count) or
// file_size (total bytes). An empty Sort means the default, file_size desc.
type ListUploadersQuery struct {
	Sort, Order   string
	Limit, Offset int
}

// validUploaderSorts whitelists the leaderboard sort columns. The HTTP layer
// validates against these; the SQL store whitelists the same set as a backstop.
var validUploaderSorts = map[string]bool{"file_count": true, "file_size": true}

// ValidUploaderSort reports whether s is an accepted ListUploadersQuery sort.
func ValidUploaderSort(s string) bool { return validUploaderSorts[s] }

// UploadStats is the aggregate view of uploads matching a query, used by the
// admin metrics endpoint. TotalSize sums the sizes recorded at presign time, so
// it includes uploads a client never completed until reconciliation prunes them;
// the over-count is transient and acceptable for the report.
type UploadStats struct {
	TotalFiles  int
	TotalSize   int64
	TotalImages int
}

// APIKey is a long-lived Depot-issued credential for external tools (ShareX,
// Puush, cURL). Only the hash is stored; the raw key is shown once at creation.
type APIKey struct {
	ID           string
	Hash         string // hash of the raw key; the raw key is never stored
	OwnerAccount string
	OwnerIssuer  string
	Label        string
	Scopes       []string
	ExpiresAt    *time.Time // nil = no expiry
	LastUsedAt   *time.Time // nil = never used
	CreatedAt    time.Time
}

// Store is the metadata seam. Backed by sqlite (single box) or postgres (the
// horizontal scale path).
type Store interface {
	// RecordUpload writes the metadata row for a presigned upload.
	RecordUpload(ctx context.Context, u Upload) error
	// DeleteUpload removes the row for objectKey, but only if it belongs to the
	// given account/issuer. Returns ErrNotFound if there is no such owned row.
	DeleteUpload(ctx context.Context, objectKey, account, issuer string) error
	// DeleteUploadAny removes the row for objectKey regardless of owner. It is
	// the moderation primitive; only an admin caller reaches it. Returns
	// ErrNotFound if there is no such row.
	DeleteUploadAny(ctx context.Context, objectKey string) error
	// WipeUploads removes every upload row owned by account, optionally narrowed
	// to issuer when it is non-empty, and returns the object keys it removed so
	// the caller can delete the backing objects. account must be non-empty; an
	// empty account would match every row, so the store rejects it. Removing zero
	// rows is not an error: it returns an empty slice.
	WipeUploads(ctx context.Context, account, issuer string) ([]string, error)
	// ListUploads returns a page of uploads matching q and the total matching
	// count (ignoring limit/offset). It serves both the self and admin listings.
	ListUploads(ctx context.Context, q ListUploadsQuery) ([]Upload, int, error)
	// Stats aggregates the uploads matching q (the same filter shape as
	// ListUploads; limit/offset/sort are ignored). It backs the admin metrics
	// endpoint.
	Stats(ctx context.Context, q ListUploadsQuery) (UploadStats, error)
	// ListUploaders returns a page of uploaders for the leaderboard, sorted per q
	// (default total bytes desc), plus the count of distinct uploaders. It backs
	// the admin per-user leaderboard.
	ListUploaders(ctx context.Context, q ListUploadersQuery) ([]UploaderUsage, int, error)
	// ContentTypes returns the distinct, non-empty content types across all
	// uploads, sorted, for the admin file-type filter.
	ContentTypes(ctx context.Context) ([]string, error)
	// Usage returns the total bytes currently attributed to account/issuer,
	// used for quota enforcement.
	Usage(ctx context.Context, account, issuer string) (int64, error)

	// CreateKey persists a new API key record.
	CreateKey(ctx context.Context, k APIKey) error
	// ListKeys returns the caller's keys (without the hash).
	ListKeys(ctx context.Context, account, issuer string) ([]APIKey, error)
	// ResolveKey looks up a key by its hash for authentication.
	ResolveKey(ctx context.Context, hash string) (APIKey, error)
	// RevokeKey deletes a key by id, but only if it belongs to account/issuer.
	RevokeKey(ctx context.Context, id, account, issuer string) error
	// TouchKey records that a key was just used (last_used tracking).
	TouchKey(ctx context.Context, id string) error

	// Close releases the underlying database resources.
	Close() error
}
