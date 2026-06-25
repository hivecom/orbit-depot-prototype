package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/hivecom/orbit-depot/internal/store"
)

// handleDeleteFile deletes a file. A normal caller needs an identity (anonymous
// uploads cannot prove ownership) and may only delete a row it owns. An admin
// caller (verified OIDC with the configured admin claim) deletes any row
// regardless of owner; that is the moderation primitive.
func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	if s.driver == nil || s.auth == nil || s.store == nil {
		writeError(w, http.StatusNotImplemented, "file deletion is not implemented yet")
		return
	}

	id, err := s.auth.Authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return
	}
	if id.Anonymous {
		writeError(w, http.StatusForbidden, "file deletion requires an authenticated identity")
		return
	}

	key := r.PathValue("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "object key is required")
		return
	}

	// Remove the metadata row first, which also verifies ownership. Doing this
	// before deleting the object means a failed object delete leaks bytes (the
	// periodic cleanup reconciles them) rather than leaving a phantom row that
	// still counts against quota. An admin bypasses the ownership predicate.
	if id.Admin {
		err = s.store.DeleteUploadAny(r.Context(), key)
	} else {
		err = s.store.DeleteUpload(r.Context(), key, id.Subject, id.Issuer)
	}
	if errors.Is(err, store.ErrNotFound) {
		// No such object, or not the caller's: one answer, so deletion reveals
		// nothing about other owners' files.
		writeError(w, http.StatusNotFound, "no such file")
		return
	}
	if err != nil {
		s.log.Error("delete upload row", "error", err, "key", key)
		writeError(w, http.StatusInternalServerError, "could not delete file")
		return
	}

	if err := s.driver.DeleteObject(r.Context(), key); err != nil {
		// The row is already gone and quota is freed; the object is now orphaned
		// and will be reconciled by cleanup. Log, but report success.
		s.log.Warn("object delete failed after row removal; orphaned", "error", err, "key", key)
	}

	w.WriteHeader(http.StatusNoContent)
}

// wipeResponse reports how many uploads a wipe removed.
type wipeResponse struct {
	Deleted int `json:"deleted"`
}

// handleWipeFiles removes every upload owned by the authenticated caller. It is
// the self-service "wipe all my uploads" path: account deletion calls it so a
// removed user leaves nothing behind, but it also stands alone. Anonymous
// callers cannot prove ownership, so they are refused like single deletion.
func (s *Server) handleWipeFiles(w http.ResponseWriter, r *http.Request) {
	if s.driver == nil || s.auth == nil || s.store == nil {
		writeError(w, http.StatusNotImplemented, "file deletion is not implemented yet")
		return
	}

	id, err := s.auth.Authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return
	}
	if id.Anonymous {
		writeError(w, http.StatusForbidden, "file deletion requires an authenticated identity")
		return
	}

	deleted, err := s.wipeUploads(r.Context(), id.Subject, id.Issuer)
	if err != nil {
		s.log.Error("wipe own uploads", "error", err)
		writeError(w, http.StatusInternalServerError, "could not wipe uploads")
		return
	}
	writeJSON(w, http.StatusOK, wipeResponse{Deleted: deleted})
}

// wipeUploads removes every upload owned by account (optionally issuer-scoped),
// mirroring single-file deletion: the metadata rows go first, which frees quota
// and settles ownership, then each backing object is deleted best-effort. A
// failed object delete leaves an orphan for the cleanup job to reconcile,
// exactly as the single-delete path does. Returns the number of rows removed.
func (s *Server) wipeUploads(ctx context.Context, account, issuer string) (int, error) {
	keys, err := s.store.WipeUploads(ctx, account, issuer)
	if err != nil {
		return 0, err
	}
	for _, key := range keys {
		if err := s.driver.DeleteObject(ctx, key); err != nil {
			s.log.Warn("object delete failed during wipe; orphaned", "error", err, "key", key)
		}
	}
	return len(keys), nil
}
