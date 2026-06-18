package auth

import "net/http"

// anonymous accepts every request as an unauthenticated caller. It is wired in
// when the operator enables the anonymous credential and there is nothing to
// verify - the caller carries no identity, so quotas and ownership do not apply.
type anonymous struct{}

// Anonymous returns an Authenticator that resolves every request to an
// anonymous Identity.
func Anonymous() Authenticator { return anonymous{} }

func (anonymous) Authenticate(*http.Request) (*Identity, error) {
	return &Identity{Anonymous: true}, nil
}
