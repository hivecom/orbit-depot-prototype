package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubToken stands in for a token authenticator without any crypto.
type stubToken struct {
	id  *Identity
	err error
}

func (s stubToken) Authenticate(*http.Request) (*Identity, error) { return s.id, s.err }

func req(bearer string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/upload/presign", nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return r
}

func TestChain(t *testing.T) {
	resolved := &Identity{Subject: "u1", Issuer: "iss"}

	t.Run("bearer delegates to token authenticator", func(t *testing.T) {
		c := Chain(stubToken{id: resolved}, false)
		id, err := c.Authenticate(req("tok"))
		if err != nil || id != resolved {
			t.Fatalf("got (%+v, %v), want resolved identity", id, err)
		}
	})

	t.Run("bearer with no token credential is unauthorized", func(t *testing.T) {
		c := Chain(nil, true) // anonymous enabled, but a token was presented
		if _, err := c.Authenticate(req("tok")); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})

	t.Run("invalid token does not fall through to anonymous", func(t *testing.T) {
		c := Chain(stubToken{err: ErrUnauthorized}, true)
		if _, err := c.Authenticate(req("tok")); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})

	t.Run("no credential resolves anonymous when enabled", func(t *testing.T) {
		id, err := Chain(stubToken{}, true).Authenticate(req(""))
		if err != nil || id == nil || !id.Anonymous {
			t.Fatalf("got (%+v, %v), want anonymous identity", id, err)
		}
	})

	t.Run("no credential is rejected when anonymous disabled", func(t *testing.T) {
		if _, err := Chain(stubToken{}, false).Authenticate(req("")); !errors.Is(err, ErrNoCredential) {
			t.Fatalf("err = %v, want ErrNoCredential", err)
		}
	})
}

func TestBearerToken(t *testing.T) {
	cases := map[string]struct {
		header string
		want   string
		wantOK bool
	}{
		"valid":        {"Bearer abc", "abc", true},
		"case-insens":  {"bearer abc", "abc", true},
		"trims spaces": {"Bearer   abc  ", "abc", true},
		"missing":      {"", "", false},
		"wrong scheme": {"Basic abc", "", false},
		"prefix only":  {"Bearer ", "", false},
	}
	for name, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.header != "" {
			r.Header.Set("Authorization", tc.header)
		}
		got, ok := bearerToken(r)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("%s: bearerToken = (%q, %v), want (%q, %v)", name, got, ok, tc.want, tc.wantOK)
		}
	}
}
