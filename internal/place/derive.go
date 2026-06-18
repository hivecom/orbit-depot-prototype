package place

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"time"
)

// anonymousOwner is the reserved owner segment for uploads with no identity. A
// real account hash is hex and never starts with an underscore, so this cannot
// collide with a user's namespace.
const anonymousOwner = "_anonymous"

// maxFilenameLen bounds the sanitized filename segment.
const maxFilenameLen = 128

// DeriveKey produces the object key for an upload. The owner segment comes from
// the verified identity (or the anonymous bucket), so the caller can only ever
// write within their own namespace. The key is never taken from client input.
func (p Place) DeriveKey(subject, issuer string, anonymous bool, req Request) (string, error) {
	owner := anonymousOwner
	if !anonymous {
		owner = accountHash(issuer, subject)
	} else if p.Strategy == StrategyAccount {
		// A deterministic per-account key needs an account; Validate already
		// rejects this, but guard the derivation too.
		return "", ErrIdentityRequired
	}

	filename := sanitizeFilename(req.Filename)

	switch p.Strategy {
	case StrategyDump:
		unique, err := uniqueSegment(time.Now())
		if err != nil {
			return "", err
		}
		return path.Join(p.Prefix, owner, unique, filename), nil
	case StrategyAccount:
		return path.Join(p.Prefix, owner, filename), nil
	default:
		return "", fmt.Errorf("unknown key strategy %q", p.Strategy)
	}
}

// accountHash is a short, stable hash of the owning identity. It derives from
// the immutable subject (sub) and issuer, never the mutable username, so a
// username change does not move a user's files. It keeps the raw account name
// out of public URLs while still grouping a user's objects for admin tooling.
func accountHash(issuer, subject string) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return hex.EncodeToString(sum[:8])
}

// uniqueSegment is a per-upload directory whose lexical order matches its
// chronological order: a sortable UTC timestamp followed by random bytes that
// break sub-second ties. Dep-free and time-ordered.
func uniqueSegment(now time.Time) (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return now.UTC().Format("20060102T150405.000") + "-" + hex.EncodeToString(b[:]), nil
}

// sanitizeFilename reduces a client-supplied name to a safe last path segment,
// preserving a readable name and its extension for the public URL.
func sanitizeFilename(name string) string {
	// Drop any directory component the client may have included.
	name = name[strings.LastIndexAny(name, "/\\")+1:]

	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}

	// Trim dots so the result is never "", ".", or "..".
	s := strings.Trim(b.String(), ".")
	if s == "" {
		return "file"
	}
	if len(s) > maxFilenameLen {
		s = s[len(s)-maxFilenameLen:] // keep the tail to preserve the extension
	}
	return s
}
