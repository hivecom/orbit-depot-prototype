// Package quota enforces per-user storage quotas. The real enforcer (New, in
// enforce.go) reads the configured default and per-account overrides and queries
// store.Usage; Allow is the permissive enforcer used when there is no identity
// to attribute (anonymous-only Depot).
//
// There is a known check-then-write race: two concurrent presigns can both pass
// before either row is written, so a user can momentarily exceed quota. For the
// MVP that is acceptable. Closing it hard is a postgres advisory lock or a Redis
// atomic reservation, not a redesign.
package quota

import "context"

// Enforcer decides whether an identified caller may upload more, and reports the
// caller's configured limit.
type Enforcer interface {
	// Check returns a non-nil error when the upload would exceed the caller's
	// quota. Implementations resolve the limit from the default and any
	// per-account override.
	Check(ctx context.Context, account, issuer string, addBytes int64) error

	// Limit returns the account's quota in bytes. A non-positive value means
	// unlimited.
	Limit(account string) int64
}

// Allow is an Enforcer that permits every upload. It is the correct enforcer for
// deployments without an identity (anonymous-only), where per-user quotas do not
// apply.
var Allow Enforcer = allowAll{}

type allowAll struct{}

func (allowAll) Check(context.Context, string, string, int64) error { return nil }
func (allowAll) Limit(string) int64                                 { return 0 }
