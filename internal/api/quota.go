package api

import "net/http"

type quotaResponse struct {
	Used      int64 `json:"used"`
	Limit     int64 `json:"limit"`
	Unlimited bool  `json:"unlimited"`
}

// handleQuota reports the authenticated caller's current usage and limit. Quotas
// apply only to identified callers, so anonymous requests are rejected.
func (s *Server) handleQuota(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil || s.store == nil {
		writeError(w, http.StatusNotImplemented, "quota reporting is not implemented yet")
		return
	}

	id, err := s.auth.Authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return
	}
	if id.Anonymous {
		writeError(w, http.StatusForbidden, "quota requires an authenticated identity")
		return
	}

	used, err := s.store.Usage(r.Context(), id.Subject, id.Issuer)
	if err != nil {
		s.log.Error("read usage", "error", err, "account", id.Subject)
		writeError(w, http.StatusInternalServerError, "could not read usage")
		return
	}

	limit := s.quota.Limit(id.Subject)
	writeJSON(w, http.StatusOK, quotaResponse{
		Used:      used,
		Limit:     limit,
		Unlimited: limit <= 0,
	})
}
