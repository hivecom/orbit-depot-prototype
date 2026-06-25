package auth

import (
	"errors"
	"testing"
)

func TestServiceKey(t *testing.T) {
	inner := &Identity{Subject: "u1", Issuer: "iss", Method: MethodOIDC}

	t.Run("matching key resolves to admin", func(t *testing.T) {
		a := ServiceKey("s3cr3t", stubToken{id: inner})
		id, err := a.Authenticate(req("s3cr3t"))
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if !id.Admin || id.Method != MethodServiceKey {
			t.Fatalf("identity = %+v, want admin service-key identity", id)
		}
		if id.Subject != ServiceAccount {
			t.Errorf("subject = %q, want %q", id.Subject, ServiceAccount)
		}
	})

	t.Run("non-matching token delegates to inner", func(t *testing.T) {
		a := ServiceKey("s3cr3t", stubToken{id: inner})
		id, err := a.Authenticate(req("a-user-jwt"))
		if err != nil || id != inner {
			t.Fatalf("got (%+v, %v), want the inner identity", id, err)
		}
	})

	t.Run("non-matching token with no inner is unauthorized", func(t *testing.T) {
		a := ServiceKey("s3cr3t", nil)
		if _, err := a.Authenticate(req("nope")); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("err = %v, want ErrUnauthorized (no silent anonymous downgrade)", err)
		}
	})

	t.Run("no bearer is no credential", func(t *testing.T) {
		a := ServiceKey("s3cr3t", nil)
		if _, err := a.Authenticate(req("")); !errors.Is(err, ErrNoCredential) {
			t.Fatalf("err = %v, want ErrNoCredential", err)
		}
	})

	t.Run("empty key returns inner unchanged", func(t *testing.T) {
		base := stubToken{id: inner}
		if got := ServiceKey("", base); got != Authenticator(base) {
			t.Fatalf("ServiceKey(\"\", inner) = %#v, want inner unchanged", got)
		}
	})
}
