// Package auth defines the second seam: who is calling. An Authenticator
// resolves a request's credentials to an Identity, or rejects it. The concrete
// authenticator is composed from the enabled credential flags (anonymous,
// oidc, api_key); each verifies independently and no Orbit component contacts
// another to check identity.
package auth

import (
	"errors"
	"net/http"
	"strings"
)

// Method is the credential class that resolved an Identity. Some endpoints
// require a specific class: key management requires a real OIDC login, never an
// API key, so a leaked key cannot mint more keys.
type Method string

const (
	MethodAnonymous Method = "anonymous"
	MethodOIDC      Method = "oidc"
	MethodAPIKey    Method = "api_key"
)

// Identity is the resolved caller. An anonymous caller has Anonymous = true and
// no subject; everything else carries the subject and issuer used for quota
// accounting, deletion rights, and audit.
//
// Identity is the immutable sub, never a renameable claim like
// preferred_username: ownership and quota must not move when a user renames.
//
// An api_key-attributed caller is indistinguishable from an oidc-attributed one
// for quota and ownership - the key path fills in the same Subject and Issuer -
// but Method still records how it was resolved, so key-management endpoints can
// insist on a genuine OIDC login. Anonymous is true exactly when Method is
// MethodAnonymous.
//
// Admin is set only on the OIDC path, when a configured claim in the verified
// token matches the operator's admin policy. It is never set for anonymous or
// api_key callers, so a leaked key cannot escalate to moderation rights.
type Identity struct {
	Subject   string // sub claim; the stable account identifier
	Issuer    string // iss claim; supports multi-server identity
	Method    Method
	Anonymous bool
	Admin     bool // an OIDC claim matched the configured admin policy
}

// Errors returned by an Authenticator. Handlers map these to HTTP status codes.
var (
	// ErrNoCredential means the request carried no credential matching any
	// enabled flag. Whether this is rejected depends on whether anonymous is
	// enabled.
	ErrNoCredential = errors.New("no matching credential")
	// ErrUnauthorized means a credential was presented but failed verification
	// (bad signature, expired, revoked key, wrong issuer/audience).
	ErrUnauthorized = errors.New("unauthorized")
)

// Authenticator resolves the request's credentials to an Identity. It tries the
// enabled credential flags and returns the first that verifies. When only
// anonymous is enabled it returns an anonymous Identity; when a token is
// presented but invalid it returns ErrUnauthorized.
type Authenticator interface {
	Authenticate(r *http.Request) (*Identity, error)
}

// bearerToken returns the token from an "Authorization: Bearer <token>" header.
// Both the oidc and api_key credentials present here, so the chain uses mere
// presence to decide whether a request carries a token credential at all.
func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	if tok := strings.TrimSpace(h[len(prefix):]); tok != "" {
		return tok, true
	}
	return "", false
}
