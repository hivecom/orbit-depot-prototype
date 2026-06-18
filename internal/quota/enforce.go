package quota

import (
	"context"
	"errors"
	"fmt"
)

// ErrExceeded is returned by Check when an upload would push the caller over
// their limit. Callers distinguish it from an infrastructure error (a failed
// usage read) to map it to the right status: over-quota is the caller's fault
// (413), a read failure is not (500).
var ErrExceeded = errors.New("quota exceeded")

// UsageReader is the slice of the metadata store the enforcer needs: the total
// bytes currently attributed to an account/issuer. store.Store satisfies it.
type UsageReader interface {
	Usage(ctx context.Context, account, issuer string) (int64, error)
}

// enforcer is the real Enforcer: it resolves the per-account limit and compares
// it against current usage from the store.
type enforcer struct {
	usage     UsageReader
	limit     int64            // default per-user limit in bytes
	overrides map[string]int64 // account (the JWT sub) -> replacement limit
}

// New returns an Enforcer backed by the store. limit is the default per-user
// quota in bytes; overrides maps an account - which, like everywhere else in
// Depot, is the JWT sub - to a replacement limit. A non-positive resolved limit
// means unlimited.
func New(usage UsageReader, limit int64, overrides map[string]int64) Enforcer {
	return &enforcer{usage: usage, limit: limit, overrides: overrides}
}

// Limit returns the account's resolved quota: its override if one exists, else
// the default.
func (e *enforcer) Limit(account string) int64 {
	if o, ok := e.overrides[account]; ok {
		return o
	}
	return e.limit
}

func (e *enforcer) Check(ctx context.Context, account, issuer string, addBytes int64) error {
	limit := e.Limit(account)
	if limit <= 0 {
		return nil // unlimited
	}

	used, err := e.usage.Usage(ctx, account, issuer)
	if err != nil {
		return fmt.Errorf("read usage: %w", err)
	}
	if used+addBytes > limit {
		return ErrExceeded
	}
	return nil
}
