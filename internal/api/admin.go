package api

import (
	"context"
	"net/http"

	"github.com/hivecom/orbit-depot/internal/auth"
	"github.com/hivecom/orbit-depot/internal/store"
)

// adminFileItem is the admin listing row: a normal file item plus the uploader
// identity, which the self listing never exposes.
type adminFileItem struct {
	fileItem
	UploaderAccount string `json:"uploader_account"`
	UploaderIssuer  string `json:"uploader_issuer"`
}

type adminListFilesResponse struct {
	Files []adminFileItem `json:"files"`
	Total int             `json:"total"`
}

// requireAdmin authenticates the caller and insists on a verified OIDC login
// whose configured admin claim matched. API keys and anonymous callers are never
// admin, mirroring how key management is closed to API keys so a leaked
// credential cannot escalate.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (*auth.Identity, bool) {
	if s.auth == nil || s.store == nil || s.driver == nil {
		writeError(w, http.StatusNotImplemented, "admin file listing is not implemented yet")
		return nil, false
	}
	id, err := s.auth.Authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return nil, false
	}
	if id.Method != auth.MethodOIDC {
		writeError(w, http.StatusForbidden, "admin access requires an OIDC login")
		return nil, false
	}
	if !id.Admin {
		writeError(w, http.StatusForbidden, "admin access required")
		return nil, false
	}
	return id, true
}

// handleAdminListFiles lists uploads across all owners. Unlike the self listing
// it does not force owner scoping, so an admin may target a specific uploader
// (account/issuer) or content type, or list everything.
func (s *Server) handleAdminListFiles(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}

	q, err := listQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	v := r.URL.Query()
	q.Account = v.Get("account")
	q.Issuer = v.Get("issuer")
	q.ContentType = v.Get("content_type")

	uploads, total, err := s.store.ListUploads(r.Context(), q)
	if err != nil {
		s.log.Error("admin list uploads", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list files")
		return
	}

	items, err := s.adminFileItems(r.Context(), uploads)
	if err != nil {
		s.log.Error("resolve download", "error", err)
		writeError(w, http.StatusInternalServerError, "could not resolve download URL")
		return
	}

	writeJSON(w, http.StatusOK, adminListFilesResponse{Files: items, Total: total})
}

type adminMetricsResponse struct {
	TotalFiles  int   `json:"total_files"`
	TotalSize   int64 `json:"total_size"`
	TotalImages int   `json:"total_images"`
}

// handleAdminMetrics reports aggregate upload counts and size. It takes the same
// owner and content-type filters as the listing, so the report can be scoped to
// one user (account/issuer) or to whatever the admin table is filtered to.
func (s *Server) handleAdminMetrics(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}

	q, err := listQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	v := r.URL.Query()
	q.Account = v.Get("account")
	q.Issuer = v.Get("issuer")
	q.ContentType = v.Get("content_type")

	stats, err := s.store.Stats(r.Context(), q)
	if err != nil {
		s.log.Error("admin metrics", "error", err)
		writeError(w, http.StatusInternalServerError, "could not load metrics")
		return
	}

	writeJSON(w, http.StatusOK, adminMetricsResponse{
		TotalFiles:  stats.TotalFiles,
		TotalSize:   stats.TotalSize,
		TotalImages: stats.TotalImages,
	})
}

// adminFileItems builds the admin rows, resolving each download URL through the
// driver the same way fileItems does and adding the uploader identity.
func (s *Server) adminFileItems(ctx context.Context, uploads []store.Upload) ([]adminFileItem, error) {
	items := make([]adminFileItem, 0, len(uploads))
	for _, u := range uploads {
		url, err := s.driver.ResolveDownload(ctx, u.ObjectKey)
		if err != nil {
			return nil, err
		}
		items = append(items, adminFileItem{
			fileItem: fileItem{
				ObjectKey:        u.ObjectKey,
				URL:              url,
				Size:             u.FileSize,
				ContentType:      u.ContentType,
				OriginalFilename: u.OriginalFilename,
				UploadedAt:       u.UploadedAt,
			},
			UploaderAccount: u.UploaderAccount,
			UploaderIssuer:  u.UploaderIssuer,
		})
	}
	return items, nil
}
