package api

import "net/http"

// healthResponse is the body of GET /health.
type healthResponse struct {
	Status string `json:"status"`
	Driver string `json:"driver"`
}

// handleHealth reports gateway reachability. Backing-store connectivity checks
// (S3 reachability, local filesystem, metadata store) are added as those seams
// are wired in.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		Status: "ok",
		Driver: s.cfg.Depot.Driver,
	})
}
