package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/hivecom/orbit-depot/internal/auth"
	"github.com/hivecom/orbit-depot/internal/store"
)

// maxKeysBody bounds the key-management request body; it is small JSON.
const maxKeysBody = 4 << 10

type createKeyRequest struct {
	Label     string   `json:"label"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at"` // optional; RFC3339 or YYYY-MM-DD
}

// keyResponse is the wire shape for a key. Key (the raw secret) is populated
// only in the create response - it is shown exactly once and never stored.
type keyResponse struct {
	ID         string     `json:"id"`
	Key        string     `json:"key,omitempty"`
	Label      string     `json:"label"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// requireOIDC authenticates the caller and insists the credential is a genuine
// OIDC login. Key management is deliberately closed to API keys so a leaked key
// cannot mint or revoke keys, and to anonymous callers who have no identity.
func (s *Server) requireOIDC(w http.ResponseWriter, r *http.Request) (*auth.Identity, bool) {
	if s.auth == nil || s.store == nil {
		writeError(w, http.StatusNotImplemented, "key management is not implemented yet")
		return nil, false
	}
	id, err := s.auth.Authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return nil, false
	}
	if id.Method != auth.MethodOIDC {
		writeError(w, http.StatusForbidden, "key management requires an OIDC login")
		return nil, false
	}
	return id, true
}

// handleCreateKey mints a long-lived API key owned by the OIDC caller and
// returns the raw key once.
func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	id, ok := s.requireOIDC(w, r)
	if !ok {
		return
	}

	var req createKeyRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxKeysBody))
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Label == "" {
		writeError(w, http.StatusBadRequest, "label is required")
		return
	}

	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		t, err := parseExpiry(req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expires_at; use RFC3339 or YYYY-MM-DD")
			return
		}
		if t.Before(time.Now()) {
			writeError(w, http.StatusBadRequest, "expires_at is in the past")
			return
		}
		expiresAt = &t
	}

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"upload"}
	}

	raw, err := auth.GenerateAPIKey()
	if err != nil {
		s.log.Error("generate api key", "error", err)
		writeError(w, http.StatusInternalServerError, "could not mint key")
		return
	}

	k := store.APIKey{
		ID:           uuid.NewString(),
		Hash:         auth.HashAPIKey(raw),
		OwnerAccount: id.Subject,
		OwnerIssuer:  id.Issuer,
		Label:        req.Label,
		Scopes:       scopes,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.store.CreateKey(r.Context(), k); err != nil {
		s.log.Error("create key", "error", err)
		writeError(w, http.StatusInternalServerError, "could not store key")
		return
	}

	writeJSON(w, http.StatusCreated, keyResponse{
		ID:        k.ID,
		Key:       raw,
		Label:     k.Label,
		Scopes:    k.Scopes,
		ExpiresAt: k.ExpiresAt,
		CreatedAt: k.CreatedAt,
	})
}

// handleListKeys returns the caller's keys, without hashes or raw secrets.
func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	id, ok := s.requireOIDC(w, r)
	if !ok {
		return
	}

	keys, err := s.store.ListKeys(r.Context(), id.Subject, id.Issuer)
	if err != nil {
		s.log.Error("list keys", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list keys")
		return
	}

	out := make([]keyResponse, 0, len(keys))
	for _, k := range keys {
		out = append(out, keyResponse{
			ID:         k.ID,
			Label:      k.Label,
			Scopes:     k.Scopes,
			ExpiresAt:  k.ExpiresAt,
			LastUsedAt: k.LastUsedAt,
			CreatedAt:  k.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

// handleRevokeKey deletes one of the caller's keys by id. Unlike a JWT, a key is
// revoked instantly.
func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	id, ok := s.requireOIDC(w, r)
	if !ok {
		return
	}

	keyID := r.PathValue("id")
	if keyID == "" {
		writeError(w, http.StatusBadRequest, "key id is required")
		return
	}

	err := s.store.RevokeKey(r.Context(), keyID, id.Subject, id.Issuer)
	if errors.Is(err, store.ErrNotFound) {
		// Either no such key, or it is not the caller's: same answer, so revoking
		// reveals nothing about other owners' keys.
		writeError(w, http.StatusNotFound, "no such key")
		return
	}
	if err != nil {
		s.log.Error("revoke key", "error", err)
		writeError(w, http.StatusInternalServerError, "could not revoke key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseExpiry accepts a full RFC3339 timestamp or a bare YYYY-MM-DD date.
func parseExpiry(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", s)
}
