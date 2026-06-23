package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// clockSkew is the tolerance applied to a token's time claims to absorb drift
// between the provider and Depot. The Orbit spec mandates +/-30s for all JWT
// verification (transponder.md, "Token Lifetime and Clock Skew").
const clockSkew = 30 * time.Second

// oidcAuth verifies a Bearer JWT against the provider's published JWKS. The
// verifier is constructed once from OIDC discovery and reused; the underlying
// key set refreshes itself when it sees an unknown key id, so provider key
// rotation needs no restart.
type oidcAuth struct {
	verifier *oidc.IDTokenVerifier
	// adminClaim is the top-level JWT claim consulted for admin status; empty
	// disables admin entirely. adminValues are the claim values that grant it.
	adminClaim  string
	adminValues []string
}

// OIDC builds an Authenticator that verifies Transponder JWTs. It performs OIDC
// discovery against issuer at construction, so a returned error means Depot
// should not start.
//
// The issuer is always enforced (a token's iss must match), which is the tenant
// boundary. The audience is enforced only when configured: a non-empty audience
// means the verifier rejects any token whose aud claim does not contain it, and
// it is never skipped. An empty audience skips the aud check, for providers that
// mint a generic shared audience (e.g. Supabase's "authenticated") where the aud
// carries no per-app signal and the issuer is the real boundary.
//
// adminClaim and adminValues set the admin policy: a verified token whose
// top-level adminClaim holds one of adminValues resolves to an admin identity.
// An empty adminClaim disables admin entirely. Depot stays generic here - it is
// told which claim to trust, never anything about the provider's user model.
func OIDC(ctx context.Context, issuer, audience, adminClaim string, adminValues []string) (Authenticator, error) {
	// A bounded client times out a hung discovery or key fetch without imposing
	// a global deadline that would later expire on the long-lived key set.
	hc := &http.Client{Timeout: 30 * time.Second}
	ctx = oidc.ClientContext(ctx, hc)

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for issuer %q: %w", issuer, err)
	}

	cfg := &oidc.Config{
		ClientID: audience,
		// Accept both RSA and EC signatures. Supabase's asymmetric JWT signing
		// keys default to ES256 (P-256); go-oidc otherwise falls back to
		// RS256-only and would reject every ES256 token. This matches the
		// orbit-auth-bridge, which accepts RS256 and ES256.
		SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256},
		// Expiry is checked here, not by go-oidc, so the spec's +/-30s clock
		// skew tolerance can be applied (go-oidc exposes no leeway knob).
		SkipExpiryCheck: true,
	}
	if audience == "" {
		// go-oidc requires either a ClientID or an explicit opt-out; an empty
		// audience is a deliberate opt-out, not a misconfiguration.
		cfg.SkipClientIDCheck = true
	}
	return &oidcAuth{
		verifier:    provider.Verifier(cfg),
		adminClaim:  adminClaim,
		adminValues: adminValues,
	}, nil
}

func (a *oidcAuth) Authenticate(r *http.Request) (*Identity, error) {
	raw, ok := bearerToken(r)
	if !ok {
		return nil, ErrNoCredential
	}

	tok, err := a.verifier.Verify(r.Context(), raw)
	if err != nil {
		// Bad signature, wrong issuer, or wrong/absent audience all land here as
		// a flat unauthorized; the detail is for logs, not callers.
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	if err := verifyTime(tok, time.Now()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}

	// Identity is the subject and nothing else. sub is the stable, immutable
	// account identifier; it is what quota accounting, ownership, and object-key
	// derivation key on. preferred_username is deliberately ignored - it can be
	// renamed, and tying identity to it would let a rename reassign ownership.
	if tok.Subject == "" {
		return nil, fmt.Errorf("%w: token has no subject", ErrUnauthorized)
	}
	id := &Identity{
		Subject: tok.Subject,
		Issuer:  tok.Issuer,
		Method:  MethodOIDC,
	}

	// Admin is read from a configured claim in the already-verified token. When
	// no admin claim is configured the feature is off and Admin stays false.
	if a.adminClaim != "" {
		var claims map[string]any
		if err := tok.Claims(&claims); err == nil {
			id.Admin = claimGrantsAdmin(claims, a.adminClaim, a.adminValues)
		}
	}
	return id, nil
}

// claimGrantsAdmin reports whether the named claim holds one of the granting
// values. The claim must be a string; a missing or non-string claim is not admin.
func claimGrantsAdmin(claims map[string]any, claim string, values []string) bool {
	v, ok := claims[claim].(string)
	if !ok {
		return false
	}
	for _, allowed := range values {
		if v == allowed {
			return true
		}
	}
	return false
}

// verifyTime enforces the token's expiry and issued-at claims with the spec's
// clock-skew tolerance. An expiry is required; a missing issued-at is allowed.
func verifyTime(tok *oidc.IDToken, now time.Time) error {
	if tok.Expiry.IsZero() {
		return fmt.Errorf("token has no expiry")
	}
	if now.After(tok.Expiry.Add(clockSkew)) {
		return fmt.Errorf("token expired")
	}
	if !tok.IssuedAt.IsZero() && tok.IssuedAt.After(now.Add(clockSkew)) {
		return fmt.Errorf("token used before issued")
	}
	return nil
}
