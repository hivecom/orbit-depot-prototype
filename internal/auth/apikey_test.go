package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hivecom/orbit-depot/internal/store"
)

// fakeKeyStore resolves a single known key by hash.
type fakeKeyStore struct {
	key        store.APIKey
	resolveErr error
	touched    string
}

func (f *fakeKeyStore) ResolveKey(_ context.Context, hash string) (store.APIKey, error) {
	if f.resolveErr != nil {
		return store.APIKey{}, f.resolveErr
	}
	if hash != f.key.Hash {
		return store.APIKey{}, store.ErrNotFound
	}
	return f.key, nil
}

func (f *fakeKeyStore) TouchKey(_ context.Context, id string) error {
	f.touched = id
	return nil
}

func TestGenerateAndHashAPIKey(t *testing.T) {
	k1, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if !strings.HasPrefix(k1, APIKeyPrefix) {
		t.Errorf("key %q missing %q prefix", k1, APIKeyPrefix)
	}
	if !looksLikeAPIKey(k1) {
		t.Errorf("looksLikeAPIKey(%q) = false", k1)
	}
	if looksLikeAPIKey("eyJhbGciOiJIUzI1NiJ9.e30.sig") {
		t.Error("a JWT was misdetected as an API key")
	}

	k2, _ := GenerateAPIKey()
	if k1 == k2 {
		t.Error("GenerateAPIKey returned duplicate keys")
	}
	if HashAPIKey(k1) == k1 {
		t.Error("hash equals the raw key")
	}
	if HashAPIKey(k1) != HashAPIKey(k1) {
		t.Error("hash is not deterministic")
	}
	if HashAPIKey(k1) == HashAPIKey(k2) {
		t.Error("distinct keys hashed equal")
	}
}

func TestAPIKeyAuthenticate(t *testing.T) {
	raw, _ := GenerateAPIKey()
	ks := &fakeKeyStore{key: store.APIKey{
		ID: "k1", Hash: HashAPIKey(raw), OwnerAccount: "user-1", OwnerIssuer: "iss",
	}}

	id, err := APIKey(ks).Authenticate(req(raw))
	if err != nil {
		t.Fatalf("Authenticate() = %v, want nil", err)
	}
	if id.Subject != "user-1" || id.Issuer != "iss" || id.Method != MethodAPIKey {
		t.Errorf("identity = %+v, want owner sub/iss via api_key", id)
	}
	if ks.touched != "k1" {
		t.Errorf("last-used not tracked: touched = %q", ks.touched)
	}
}

func TestAPIKeyRejects(t *testing.T) {
	raw, _ := GenerateAPIKey()
	base := store.APIKey{ID: "k1", Hash: HashAPIKey(raw), OwnerAccount: "u", OwnerIssuer: "i"}

	t.Run("unknown key", func(t *testing.T) {
		other, _ := GenerateAPIKey()
		if _, err := APIKey(&fakeKeyStore{key: base}).Authenticate(req(other)); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})

	t.Run("expired key", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		k := base
		k.ExpiresAt = &past
		if _, err := APIKey(&fakeKeyStore{key: k}).Authenticate(req(raw)); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})

	t.Run("not-yet-expired key is valid", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		k := base
		k.ExpiresAt = &future
		if _, err := APIKey(&fakeKeyStore{key: k}).Authenticate(req(raw)); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
	})

	t.Run("no bearer", func(t *testing.T) {
		if _, err := APIKey(&fakeKeyStore{key: base}).Authenticate(req("")); !errors.Is(err, ErrNoCredential) {
			t.Fatalf("err = %v, want ErrNoCredential", err)
		}
	})

	t.Run("store error denies", func(t *testing.T) {
		a := APIKey(&fakeKeyStore{resolveErr: errors.New("db down")})
		if _, err := a.Authenticate(req(raw)); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})
}

func TestTokenRouter(t *testing.T) {
	oidcID := &Identity{Subject: "o", Method: MethodOIDC}
	keyID := &Identity{Subject: "k", Method: MethodAPIKey}
	apiKey, _ := GenerateAPIKey()
	const jwtish = "eyJhbGciOiJIUzI1NiJ9.e30.sig"

	t.Run("api key routes to apikey authenticator", func(t *testing.T) {
		r := TokenRouter(stubToken{id: oidcID}, stubToken{id: keyID})
		if id, err := r.Authenticate(req(apiKey)); err != nil || id != keyID {
			t.Fatalf("got (%+v, %v), want key identity", id, err)
		}
	})

	t.Run("jwt routes to oidc authenticator", func(t *testing.T) {
		r := TokenRouter(stubToken{id: oidcID}, stubToken{id: keyID})
		if id, err := r.Authenticate(req(jwtish)); err != nil || id != oidcID {
			t.Fatalf("got (%+v, %v), want oidc identity", id, err)
		}
	})

	t.Run("api key with apikey disabled is unauthorized", func(t *testing.T) {
		r := TokenRouter(stubToken{id: oidcID}, nil)
		if _, err := r.Authenticate(req(apiKey)); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})

	t.Run("jwt with oidc disabled is unauthorized", func(t *testing.T) {
		r := TokenRouter(nil, stubToken{id: keyID})
		if _, err := r.Authenticate(req(jwtish)); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})

	t.Run("no bearer is no credential", func(t *testing.T) {
		r := TokenRouter(stubToken{id: oidcID}, stubToken{id: keyID})
		if _, err := r.Authenticate(req("")); !errors.Is(err, ErrNoCredential) {
			t.Fatalf("err = %v, want ErrNoCredential", err)
		}
	})
}
