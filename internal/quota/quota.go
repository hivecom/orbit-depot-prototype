// Package quota is the carve-out for per-user storage quota enforcement.
//
// Enforcement is deferred. The seam exists now so the presign path can call it
// from day one; the real Enforcer (which reads the configured default and
// per-account overrides and queries store.Usage) lands later. Until then,
// wiring uses Allow, which permits everything.
//
// When the real enforcer arrives there is a known check-then-write race: two
// concurrent presigns can both pass before either row is written, so a user can
// momentarily exceed quota. For the MVP that is acceptable. Closing it hard is
// a postgres advisory lock or a Redis atomic reservation, not a redesign.
package quota

import "context"

// Enforcer decides whether an identified caller may upload addBytes more.
type Enforcer interface {
	// Check returns a non-nil error when the upload would exceed the caller's
	// quota. Implementations resolve the limit from the default and any
	// per-account override.
	Check(ctx context.Context, account, issuer string, addBytes int64) error
}

// Allow is an Enforcer that permits every upload. It stands in until real quota
// enforcement is implemented, and remains the correct enforcer for deployments
// without an identity (anonymous-only), where per-user quotas do not apply.
var Allow Enforcer = allowAll{}

type allowAll struct{}

func (allowAll) Check(context.Context, string, string, int64) error { return nil }
