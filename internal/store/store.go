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
	UploaderAccount  string // from the JWT sub / preferred_username, or the API key owner
	UploaderIssuer   string // from the JWT iss; supports multi-server identity
	FileSize         int64
	ContentType      string
	OriginalFilename string
	UploadedAt       time.Time
	// AllowedRecipients is reserved for recipient-scoped DM uploads (NEXT).
	// AllowedRecipients []string
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
