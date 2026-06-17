// Package storage defines the first seam: where bytes live. A Driver is a small
// interface over an object backend. The client API contract is identical for
// every driver: the client always asks Depot to presign an upload and then
// transfers to whatever URL it gets back. It never knows which backend is
// behind Depot.
package storage

import (
	"context"
	"net/http"
	"time"
)

// Constraints are the per-upload limits baked into a presigned upload. With the
// s3 driver these become part of the signature so the backend enforces them;
// with the fs driver Depot enforces them itself while proxying.
type Constraints struct {
	ContentType string
	MaxSize     int64
	Expiry      time.Duration
}

// UploadTarget is what the client needs to perform the upload. For the s3
// driver URL is a presigned PUT on the backend (bytes bypass Depot). For the
// fs driver URL points back at Depot, which writes the bytes to disk.
type UploadTarget struct {
	URL       string
	Method    string            // usually "PUT"
	Headers   map[string]string // headers the client must send to match the signature
	ObjectKey string
	ExpiresIn int // seconds until URL expiry
}

// Driver is the storage seam.
type Driver interface {
	// PresignUpload returns an upload target for the given object key under the
	// supplied constraints.
	PresignUpload(ctx context.Context, key string, c Constraints) (UploadTarget, error)

	// ResolveDownload returns a URL the client can GET for the object. For
	// public objects this is a direct backend URL; for private objects it is a
	// short-lived presigned GET (s3) or a Depot-served path (fs).
	ResolveDownload(ctx context.Context, key string) (string, error)
}

// ProxyDriver is implemented by drivers that move bytes through Depot itself
// rather than handing the client a backend URL. The fs driver implements this;
// the s3 driver does not. The API mounts these handlers on the proxied
// transfer routes only when the active driver is a ProxyDriver.
type ProxyDriver interface {
	Driver

	// UploadHandler receives proxied PUTs and writes them to the backend.
	UploadHandler() http.Handler

	// DownloadHandler serves objects from the backend.
	DownloadHandler() http.Handler
}
