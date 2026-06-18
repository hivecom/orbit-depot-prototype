package auth

import "net/http"

// chain composes the enabled credential authenticators. A request carrying a
// Bearer token is resolved by the token authenticator (oidc, later api_key); a
// request with no credential resolves to anonymous when that credential is
// enabled, and is rejected otherwise.
//
// A presented-but-invalid token never falls through to anonymous: that would be
// a silent downgrade from "tried to authenticate and failed" to "anonymous".
type chain struct {
	token     Authenticator // resolves Bearer tokens; nil when no token credential is enabled
	anonymous bool
}

// Chain returns an Authenticator composed from the enabled credentials. token
// may be nil when only anonymous is enabled.
func Chain(token Authenticator, anonymous bool) Authenticator {
	return chain{token: token, anonymous: anonymous}
}

// TokenRouter dispatches a Bearer token to the right verifier by its shape: a
// Depot API key (by prefix) goes to apikey, anything else (a JWT) to oidc.
// Either may be nil when that credential is disabled; a token whose shape maps
// to a disabled credential is rejected rather than misrouted.
func TokenRouter(oidc, apikey Authenticator) Authenticator {
	return tokenRouter{oidc: oidc, apikey: apikey}
}

type tokenRouter struct {
	oidc   Authenticator
	apikey Authenticator
}

func (r tokenRouter) Authenticate(req *http.Request) (*Identity, error) {
	raw, ok := bearerToken(req)
	if !ok {
		return nil, ErrNoCredential
	}
	if looksLikeAPIKey(raw) {
		if r.apikey == nil {
			return nil, ErrUnauthorized
		}
		return r.apikey.Authenticate(req)
	}
	if r.oidc == nil {
		return nil, ErrUnauthorized
	}
	return r.oidc.Authenticate(req)
}

func (c chain) Authenticate(r *http.Request) (*Identity, error) {
	if _, ok := bearerToken(r); ok {
		if c.token == nil {
			// A credential was presented but no token credential is enabled.
			return nil, ErrUnauthorized
		}
		return c.token.Authenticate(r)
	}
	if c.anonymous {
		return &Identity{Method: MethodAnonymous, Anonymous: true}, nil
	}
	return nil, ErrNoCredential
}
