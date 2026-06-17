// Package auth defines the second seam: who is calling. An Authenticator
// resolves a request's credentials to an Identity, or rejects it. The concrete
// authenticator is composed from the enabled credential flags (anonymous,
// oidc, api_key); each verifies independently and no Orbit component contacts
// another to check identity.
package auth

import (
	"errors"
	"net/http"
)

// Identity is the resolved caller. An anonymous caller has Anonymous = true and
// no account; everything else carries the account and issuer used for quota
// accounting, deletion rights, and audit.
//
// An api_key-attributed caller is indistinguishable from an oidc-attributed one
// once resolved: the key path fills in the same Account and Issuer.
type Identity struct {
	Account   string // preferred_username claim, or the API key owner
	Subject   string // sub claim
	Issuer    string // iss claim; supports multi-server identity
	Anonymous bool
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
