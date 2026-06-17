// Package ratelimit defines the fourth seam: request throttling. A Limiter
// decides whether an event for a given key is permitted under a rate.
//
// Two implementations back this seam. An in-memory limiter is the default and
// is correct for a single instance (the fs / single-box shape). A Redis-backed
// limiter shares counters across instances so Depot can run horizontally behind
// a load balancer (the s3 + postgres + redis shape). The seam is the same; only
// the wiring at boot differs.
package ratelimit

import (
	"context"
	"time"
)

// Limiter throttles events identified by key. The key is typically a client IP
// or an account identifier; callers choose the key to scope the limit (per-IP
// vs per-user).
type Limiter interface {
	// Allow reports whether one more event for key is permitted, given that at
	// most limit events are allowed per window. It returns false when the limit
	// is exceeded. A non-nil error means the limiter backend failed; callers
	// decide whether to fail open or closed.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}
