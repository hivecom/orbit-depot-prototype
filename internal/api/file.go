package api

import (
	"errors"
	"net/http"

	"github.com/hivecom/orbit-depot/internal/store"
)

// handleDeleteFile deletes a file the caller uploaded. It requires an identity
// (anonymous uploads cannot prove ownership) and only deletes a row owned by
// that identity. Operators delete out of band at the backend; Depot does not
// gate that.
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
	// still counts against quota.
	err = s.store.DeleteUpload(r.Context(), key, id.Subject, id.Issuer)
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
