package auth

import (
	"crypto/subtle"
	"net/http"
)

// ServiceAccount is the reserved subject attributed to a service-key caller.
// Like the anonymous owner it is not a real user; it exists so the caller has a
// stable identity on the rare self-scoped endpoint, while its real purpose is
// admin access (Admin is set, so requireAdmin accepts it).
const ServiceAccount = "_service"

// serviceKeyAuth is a static master credential. A Bearer token equal to the
// configured key (compared in constant time) resolves to a full-admin identity
// with no provider round-trip. It is the escape hatch for trusted server-to-
// server callers that cannot carry a user's OIDC token (the Hivecom backend's
// account-deletion cleanup). Because it bypasses OIDC, the operator enables it
// deliberately and supplies the key out of band (an environment variable),
// never in the config file.
type serviceKeyAuth struct {
	key   []byte
	inner Authenticator // tried when the token is not the service key; may be nil
}

// ServiceKey wraps inner with a static admin key. A presented Bearer token that
// equals key authenticates as admin; any other token falls through to inner.
// When inner is nil, a non-matching token is rejected (a token was presented but
// no other token credential is enabled) rather than downgraded to anonymous. An
// empty key returns inner unchanged, so a disabled service key adds nothing.
func ServiceKey(key string, inner Authenticator) Authenticator {
	if key == "" {
		return inner
	}
	return serviceKeyAuth{key: []byte(key), inner: inner}
}

func (a serviceKeyAuth) Authenticate(r *http.Request) (*Identity, error) {
	raw, ok := bearerToken(r)
	if !ok {
		return nil, ErrNoCredential
	}

	// Constant-time compare so a timing side channel cannot leak the key.
	// ConstantTimeCompare returns 0 for unequal lengths too, so a short guess
	// reveals nothing about the length either.
	if subtle.ConstantTimeCompare([]byte(raw), a.key) == 1 {
		return &Identity{
			Subject: ServiceAccount,
			Issuer:  ServiceAccount,
			Method:  MethodServiceKey,
			Admin:   true,
		}, nil
	}

	if a.inner == nil {
		// A token was presented and it is not the service key; with no other token
		// credential enabled it cannot authenticate. Reject rather than fall
		// through to anonymous, matching the chain's no-silent-downgrade rule.
		return nil, ErrUnauthorized
	}
	return a.inner.Authenticate(r)
}
