package api

import (
	"fmt"
	"net/http"
	"os"
)

// handleRoot answers GET /. When an index_file is configured it serves that HTML
// file; otherwise it returns a plaintext summary of Depot with project links. A
// configured-but-unreadable file (deleted after boot) falls back to the summary
// rather than failing the request.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if path := s.cfg.Depot.IndexFile; path != "" {
		html, err := os.ReadFile(path)
		if err != nil {
			s.log.Error("read index_file, falling back to default root page", "path", path, "error", err)
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(html)
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, rootInfo, s.version)
}

// rootInfo is the default plaintext root page. The single %s is the build
// version. Depot has no UI; this is just a signpost back to the project.
const rootInfo = `Orbit Depot %s

A thin S3/disk storage policy-and-signing gateway for the Orbit project. It holds
the storage credentials, decides who may upload what, and signs or proxies the
transfer. It has no UI of its own; the Orbit client is the UI.

Links
  Depot       https://github.com/hivecom/orbit-depot-prototype
  Orbit       https://github.com/hivecom/orbit
  Spec        https://github.com/hivecom/orbit-spec

Health        /health
`
