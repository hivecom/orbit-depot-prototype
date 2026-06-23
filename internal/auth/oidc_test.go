package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testIdP is a minimal OIDC provider: a signing key, a discovery document, and a
// JWKS endpoint. It mints JWTs so the verifier exercises the real signature and
// claim checks rather than a mock. alg selects RS256 or ES256 to cover both the
// RSA and EC signing keys a provider may publish.
type testIdP struct {
	t      *testing.T
	alg    string
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	issuer string
	server *httptest.Server
}

const testKID = "test-key"

// newTestIdP builds an RS256 provider; most cases don't care about the algorithm.
func newTestIdP(t *testing.T) *testIdP { return newTestIdPAlg(t, "RS256") }

func newTestIdPAlg(t *testing.T, alg string) *testIdP {
	t.Helper()
	idp := &testIdP{t: t, alg: alg}

	var jwk map[string]any
	switch alg {
	case "RS256":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate rsa key: %v", err)
		}
		idp.rsaKey = key
		jwk = map[string]any{
			"kty": "RSA", "kid": testKID, "alg": "RS256", "use": "sig",
			"n": b64(key.PublicKey.N.Bytes()), "e": b64(bigEndian(key.PublicKey.E)),
		}
	case "ES256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ec key: %v", err)
		}
		idp.ecKey = key
		jwk = map[string]any{
			"kty": "EC", "kid": testKID, "alg": "ES256", "use": "sig", "crv": "P-256",
			"x": b64(leftPad(key.X.Bytes(), 32)), "y": b64(leftPad(key.Y.Bytes(), 32)),
		}
	default:
		t.Fatalf("unsupported test alg %q", alg)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":   idp.issuer,
			"jwks_uri": idp.issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]any{jwk}})
	})

	idp.server = httptest.NewServer(mux)
	idp.issuer = idp.server.URL
	t.Cleanup(idp.server.Close)
	return idp
}

// mint signs the given claims as a JWT with the provider's configured algorithm.
func (idp *testIdP) mint(claims map[string]any) string {
	idp.t.Helper()
	header := b64(mustJSON(idp.t, map[string]any{"alg": idp.alg, "typ": "JWT", "kid": testKID}))
	payload := b64(mustJSON(idp.t, claims))
	signingInput := header + "." + payload
	h := sha256.Sum256([]byte(signingInput))

	var sig []byte
	switch idp.alg {
	case "RS256":
		s, err := rsa.SignPKCS1v15(rand.Reader, idp.rsaKey, crypto.SHA256, h[:])
		if err != nil {
			idp.t.Fatalf("rsa sign: %v", err)
		}
		sig = s
	case "ES256":
		r, s, err := ecdsa.Sign(rand.Reader, idp.ecKey, h[:])
		if err != nil {
			idp.t.Fatalf("ec sign: %v", err)
		}
		// JWS ES256 is raw r||s, each left-padded to the 32-byte coordinate size.
		sig = append(leftPad(r.Bytes(), 32), leftPad(s.Bytes(), 32)...)
	}
	return signingInput + "." + b64(sig)
}

// claims returns a baseline valid claim set; callers override fields per case.
func (idp *testIdP) claims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": idp.issuer,
		"sub": "user-123",
		"aud": "orbit",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

func newOIDC(t *testing.T, idp *testIdP, audience string) Authenticator {
	t.Helper()
	a, err := OIDC(context.Background(), idp.issuer, audience, "", nil)
	if err != nil {
		t.Fatalf("OIDC(): %v", err)
	}
	return a
}

func newOIDCAdmin(t *testing.T, idp *testIdP, audience, claim string, values []string) Authenticator {
	t.Helper()
	a, err := OIDC(context.Background(), idp.issuer, audience, claim, values)
	if err != nil {
		t.Fatalf("OIDC(): %v", err)
	}
	return a
}

func TestOIDCAcceptsValidToken(t *testing.T) {
	idp := newTestIdP(t)
	a := newOIDC(t, idp, "orbit")

	id, err := a.Authenticate(req(idp.mint(idp.claims())))
	if err != nil {
		t.Fatalf("Authenticate() = %v, want nil", err)
	}
	if id.Subject != "user-123" || id.Issuer != idp.issuer {
		t.Errorf("identity = %+v, want sub=user-123 iss=%s", id, idp.issuer)
	}
	if id.Anonymous {
		t.Error("verified identity is marked anonymous")
	}
}

// The hardening proof: a token whose aud is for a different client must be
// rejected even though it is correctly signed by this issuer's key.
func TestOIDCRejectsWrongAudience(t *testing.T) {
	idp := newTestIdP(t)
	a := newOIDC(t, idp, "orbit")

	c := idp.claims()
	c["aud"] = "some-other-client"
	if _, err := a.Authenticate(req(idp.mint(c))); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authenticate() = %v, want ErrUnauthorized", err)
	}
}

// An array aud is valid as long as it contains the configured audience.
func TestOIDCAcceptsAudienceArray(t *testing.T) {
	idp := newTestIdP(t)
	a := newOIDC(t, idp, "orbit")

	c := idp.claims()
	c["aud"] = []string{"some-other-client", "orbit"}
	if _, err := a.Authenticate(req(idp.mint(c))); err != nil {
		t.Fatalf("Authenticate() = %v, want nil for aud array containing orbit", err)
	}

	c["aud"] = []string{"a", "b"}
	if _, err := a.Authenticate(req(idp.mint(c))); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authenticate() = %v, want ErrUnauthorized for aud array without orbit", err)
	}
}

func TestOIDCRejectsExpiredAndWrongIssuer(t *testing.T) {
	idp := newTestIdP(t)
	a := newOIDC(t, idp, "orbit")

	expired := idp.claims()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()
	if _, err := a.Authenticate(req(idp.mint(expired))); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expired token: err = %v, want ErrUnauthorized", err)
	}

	wrongIss := idp.claims()
	wrongIss["iss"] = "https://evil.example.com"
	if _, err := a.Authenticate(req(idp.mint(wrongIss))); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("wrong issuer: err = %v, want ErrUnauthorized", err)
	}
}

// The spec mandates +/-30s clock-skew tolerance on time claims.
func TestOIDCClockSkew(t *testing.T) {
	idp := newTestIdP(t)
	a := newOIDC(t, idp, "orbit")
	now := time.Now()

	withinLeeway := idp.claims()
	withinLeeway["exp"] = now.Add(-10 * time.Second).Unix() // expired, but inside skew
	if _, err := a.Authenticate(req(idp.mint(withinLeeway))); err != nil {
		t.Errorf("token expired 10s ago: err = %v, want accepted within skew", err)
	}

	beyondLeeway := idp.claims()
	beyondLeeway["exp"] = now.Add(-60 * time.Second).Unix()
	if _, err := a.Authenticate(req(idp.mint(beyondLeeway))); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("token expired 60s ago: err = %v, want ErrUnauthorized", err)
	}

	future := idp.claims()
	future["iat"] = now.Add(60 * time.Second).Unix()
	if _, err := a.Authenticate(req(idp.mint(future))); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("token issued 60s in future: err = %v, want ErrUnauthorized", err)
	}

	noExp := idp.claims()
	delete(noExp, "exp")
	if _, err := a.Authenticate(req(idp.mint(noExp))); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("token without exp: err = %v, want ErrUnauthorized", err)
	}
}

// A token with no sub cannot resolve to an identity: ownership and quota key on
// sub, so a blank subject would collapse every such caller into one shared
// account. Reject it.
func TestOIDCRejectsEmptySubject(t *testing.T) {
	idp := newTestIdP(t)
	a := newOIDC(t, idp, "orbit")

	c := idp.claims()
	delete(c, "sub")
	if _, err := a.Authenticate(req(idp.mint(c))); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authenticate() = %v, want ErrUnauthorized", err)
	}
}

// Supabase's asymmetric signing keys default to ES256. The orbit-auth-bridge
// accepts ES256, so Depot must too - go-oidc's RS256-only default would reject
// every token from such a project.
func TestOIDCAcceptsES256(t *testing.T) {
	idp := newTestIdPAlg(t, "ES256")
	a := newOIDC(t, idp, "orbit")

	id, err := a.Authenticate(req(idp.mint(idp.claims())))
	if err != nil {
		t.Fatalf("Authenticate() = %v, want nil for ES256 token", err)
	}
	if id.Subject != "user-123" {
		t.Errorf("identity = %+v, want sub=user-123", id)
	}
}

func TestOIDCRejectsBadSignature(t *testing.T) {
	idp := newTestIdP(t)
	a := newOIDC(t, idp, "orbit")

	tok := idp.mint(idp.claims())
	tampered := tok[:len(tok)-2] + "xx" // corrupt the signature segment
	if _, err := a.Authenticate(req(tampered)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authenticate() = %v, want ErrUnauthorized", err)
	}
}

func TestOIDCNoBearerIsNoCredential(t *testing.T) {
	idp := newTestIdP(t)
	a := newOIDC(t, idp, "orbit")

	if _, err := a.Authenticate(req("")); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("Authenticate() = %v, want ErrNoCredential", err)
	}
}

// With no audience configured, the aud check is skipped: a token bearing any
// audience (e.g. Supabase's generic "authenticated") is accepted as long as the
// signature, issuer, and expiry hold. The issuer remains the boundary.
func TestOIDCWithoutAudienceSkipsAudCheck(t *testing.T) {
	idp := newTestIdP(t)
	a := newOIDC(t, idp, "")

	c := idp.claims()
	c["aud"] = "authenticated"
	id, err := a.Authenticate(req(idp.mint(c)))
	if err != nil {
		t.Fatalf("Authenticate() = %v, want nil when audience is unconfigured", err)
	}
	if id.Subject != "user-123" {
		t.Errorf("identity = %+v, want sub=user-123", id)
	}

	// Issuer is still enforced even with the aud check off.
	wrongIss := idp.claims()
	wrongIss["iss"] = "https://evil.example.com"
	if _, err := a.Authenticate(req(idp.mint(wrongIss))); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("wrong issuer with no audience: err = %v, want ErrUnauthorized", err)
	}
}

// Admin status is read from a configured claim in the verified token: a matching
// value grants it, a non-matching value or absent claim does not.
func TestOIDCAdminClaim(t *testing.T) {
	idp := newTestIdP(t)
	a := newOIDCAdmin(t, idp, "orbit", "user_role", []string{"admin", "moderator"})

	cases := map[string]struct {
		role      any // omitted when nil
		wantAdmin bool
	}{
		"matching value grants admin":     {"admin", true},
		"second matching value grants":    {"moderator", true},
		"non-matching value is not admin": {"user", false},
		"absent claim is not admin":       {nil, false},
		"non-string claim is not admin":   {true, false},
	}
	for name, tc := range cases {
		c := idp.claims()
		if tc.role != nil {
			c["user_role"] = tc.role
		}
		id, err := a.Authenticate(req(idp.mint(c)))
		if err != nil {
			t.Fatalf("%s: Authenticate() = %v, want nil", name, err)
		}
		if id.Admin != tc.wantAdmin {
			t.Errorf("%s: Admin = %v, want %v", name, id.Admin, tc.wantAdmin)
		}
	}
}

// With no admin claim configured, the feature is off: even a token carrying a
// role claim resolves to a non-admin identity.
func TestOIDCAdminDisabledByDefault(t *testing.T) {
	idp := newTestIdP(t)
	a := newOIDC(t, idp, "orbit")

	c := idp.claims()
	c["user_role"] = "admin"
	id, err := a.Authenticate(req(idp.mint(c)))
	if err != nil {
		t.Fatalf("Authenticate() = %v, want nil", err)
	}
	if id.Admin {
		t.Error("Admin = true with no admin claim configured, want false")
	}
}

// --- helpers ---

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// leftPad zero-pads b on the left to size bytes, the fixed-width encoding JWS
// uses for EC signature components and coordinates.
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func bigEndian(i int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(i))
	// strip leading zero bytes to the minimal big-endian representation
	n := 0
	for n < len(b)-1 && b[n] == 0 {
		n++
	}
	return b[n:]
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
