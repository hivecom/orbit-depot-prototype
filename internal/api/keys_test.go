package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hivecom/orbit-depot/internal/auth"
	"github.com/hivecom/orbit-depot/internal/config"
	"github.com/hivecom/orbit-depot/internal/store/sqlite"
)

type keyList struct {
	Keys []keyResponse `json:"keys"`
}

func keysStore(t *testing.T) *sqlite.Store {
	t.Helper()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "depot.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// keysServerOn builds a key-management server over a given store and identity,
// so tests can share one store across two callers to check ownership scoping.
func keysServerOn(st *sqlite.Store, id *auth.Identity) *Server {
	cfg := &config.Config{Depot: config.Depot{Driver: "fs"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, log, Deps{Auth: fixedAuth{id}, Store: st})
}

func oidcID(sub string) *auth.Identity {
	return &auth.Identity{Subject: sub, Issuer: "iss", Method: auth.MethodOIDC}
}

func bearerReq(bearer string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	return r
}

func TestKeysLifecycle(t *testing.T) {
	st := keysStore(t)
	s := keysServerOn(st, oidcID("user-1"))

	// Mint.
	rec := postJSON(t, s, "/keys", `{"label":"ShareX"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /keys = %d (%s), want 201", rec.Code, rec.Body.String())
	}
	var created keyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if !strings.HasPrefix(created.Key, auth.APIKeyPrefix) {
		t.Fatalf("minted key %q missing prefix", created.Key)
	}
	if created.ID == "" || len(created.Scopes) != 1 || created.Scopes[0] != "upload" {
		t.Fatalf("created = %+v, want id and default upload scope", created)
	}

	// The minted key authenticates as its owner.
	resolved, err := auth.APIKey(st).Authenticate(bearerReq(created.Key))
	if err != nil {
		t.Fatalf("minted key does not authenticate: %v", err)
	}
	if resolved.Subject != "user-1" || resolved.Method != auth.MethodAPIKey {
		t.Errorf("resolved = %+v, want owner sub via api_key", resolved)
	}

	// List shows it, without the raw secret.
	rec = do(t, s, http.MethodGet, "/keys")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /keys = %d", rec.Code)
	}
	var list keyList
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Keys) != 1 || list.Keys[0].Key != "" {
		t.Fatalf("list = %+v, want exactly one key with no raw secret", list.Keys)
	}

	// Revoke, then it is gone and no longer authenticates.
	rec = do(t, s, http.MethodDelete, "/keys/"+created.ID)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /keys = %d, want 204", rec.Code)
	}
	rec = do(t, s, http.MethodGet, "/keys")
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Keys) != 0 {
		t.Fatalf("after revoke list = %+v, want empty", list.Keys)
	}
	if _, err := auth.APIKey(st).Authenticate(bearerReq(created.Key)); err == nil {
		t.Error("revoked key still authenticates")
	}
}

func TestKeysRequireOIDC(t *testing.T) {
	// An API-key-attributed caller must not manage keys.
	s := keysServerOn(keysStore(t), &auth.Identity{Subject: "u", Issuer: "iss", Method: auth.MethodAPIKey})
	if rec := postJSON(t, s, "/keys", `{"label":"x"}`); rec.Code != http.StatusForbidden {
		t.Errorf("POST /keys via api_key = %d, want 403", rec.Code)
	}
	if rec := do(t, s, http.MethodGet, "/keys"); rec.Code != http.StatusForbidden {
		t.Errorf("GET /keys via api_key = %d, want 403", rec.Code)
	}
}

func TestCreateKeyValidation(t *testing.T) {
	s := keysServerOn(keysStore(t), oidcID("u"))
	if rec := postJSON(t, s, "/keys", `{}`); rec.Code != http.StatusBadRequest {
		t.Errorf("POST /keys without label = %d, want 400", rec.Code)
	}
	if rec := postJSON(t, s, "/keys", `{"label":"x","expires_at":"2000-01-01"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("POST /keys with past expiry = %d, want 400", rec.Code)
	}
}

func TestRevokeUnknownKey(t *testing.T) {
	s := keysServerOn(keysStore(t), oidcID("u"))
	if rec := do(t, s, http.MethodDelete, "/keys/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("DELETE unknown key = %d, want 404", rec.Code)
	}
}

// A key belongs to one owner: another OIDC user can neither see nor revoke it.
func TestKeysOwnerIsolation(t *testing.T) {
	st := keysStore(t)
	a := keysServerOn(st, oidcID("A"))
	b := keysServerOn(st, oidcID("B"))

	var created keyResponse
	rec := postJSON(t, a, "/keys", `{"label":"A's key"}`)
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	var list keyList
	rec = do(t, b, http.MethodGet, "/keys")
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Keys) != 0 {
		t.Errorf("B sees A's keys: %+v", list.Keys)
	}

	if rec := do(t, b, http.MethodDelete, "/keys/"+created.ID); rec.Code != http.StatusNotFound {
		t.Errorf("B revoking A's key = %d, want 404", rec.Code)
	}

	rec = do(t, a, http.MethodGet, "/keys")
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Keys) != 1 {
		t.Errorf("A lost their key after B's attempt: %+v", list.Keys)
	}
}
