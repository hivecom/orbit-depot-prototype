package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hivecom/orbit-depot/internal/store"
)

// APIKeyPrefix marks a Depot-issued API key. It distinguishes a key from a JWT
// in the Authorization header (so the router can dispatch without a failed JWT
// parse) and makes leaked keys greppable by secret scanners.
const APIKeyPrefix = "depot_"

// apiKeyBytes is the entropy in a generated key: 32 bytes = 256 bits.
const apiKeyBytes = 32

// KeyStore is the slice of the metadata store the API-key authenticator needs.
type KeyStore interface {
	ResolveKey(ctx context.Context, hash string) (store.APIKey, error)
	TouchKey(ctx context.Context, id string) error
}

// GenerateAPIKey returns a new random raw key, shown to the user exactly once.
// Only its hash is ever stored.
func GenerateAPIKey() (string, error) {
	b := make([]byte, apiKeyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate api key: %w", err)
	}
	return APIKeyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashAPIKey hashes a raw key for storage and lookup. A key is high-entropy
// random, so a fast SHA-256 is the right primitive - unlike a password, it needs
// no slow KDF, and constant-time comparison is handled by the unique-hash lookup.
func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// looksLikeAPIKey reports whether a bearer token is a Depot API key rather than
// a JWT, by its prefix.
func looksLikeAPIKey(raw string) bool {
	return strings.HasPrefix(raw, APIKeyPrefix)
}

// apiKeyAuth resolves a Bearer API key to its owner identity.
type apiKeyAuth struct {
	keys KeyStore
}

// APIKey returns an Authenticator that resolves Depot API keys against the store.
func APIKey(keys KeyStore) Authenticator { return &apiKeyAuth{keys: keys} }

func (a *apiKeyAuth) Authenticate(r *http.Request) (*Identity, error) {
	raw, ok := bearerToken(r)
	if !ok {
		return nil, ErrNoCredential
	}

	k, err := a.keys.ResolveKey(r.Context(), HashAPIKey(raw))
	if err != nil {
		// Unknown or revoked key (ErrNotFound) and any lookup failure both deny;
		// a key either resolves to a live owner or it does not authenticate.
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return nil, fmt.Errorf("%w: api key expired", ErrUnauthorized)
	}

	// Last-used tracking is advisory; never fail an otherwise-valid request on it.
	_ = a.keys.TouchKey(r.Context(), k.ID)

	return &Identity{
		Subject: k.OwnerAccount,
		Issuer:  k.OwnerIssuer,
		Method:  MethodAPIKey,
	}, nil
}
