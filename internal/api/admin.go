package api

import (
	"context"
	"fmt"
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

type uploaderItem struct {
	Account string `json:"account"`
	Issuer  string `json:"issuer"`
	Files   int    `json:"files"`
	Bytes   int64  `json:"bytes"`
}

type adminListUploadersResponse struct {
	Users []uploaderItem `json:"users"`
	Total int            `json:"total"`
}

// handleAdminListUploaders ranks uploaders for the per-user leaderboard, by
// total bytes (default) or upload count. Account is the raw subject; the client
// resolves it to a name.
func (s *Server) handleAdminListUploaders(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}

	q, err := uploadersQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	usage, total, err := s.store.ListUploaders(r.Context(), q)
	if err != nil {
		s.log.Error("admin list uploaders", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list uploaders")
		return
	}

	items := make([]uploaderItem, 0, len(usage))
	for _, u := range usage {
		items = append(items, uploaderItem{Account: u.Account, Issuer: u.Issuer, Files: u.Files, Bytes: u.Bytes})
	}
	writeJSON(w, http.StatusOK, adminListUploadersResponse{Users: items, Total: total})
}

// uploadersQuery parses the leaderboard paging and sort params. It mirrors
// listQuery but validates sort against the uploader aggregates (file_count,
// file_size) since the leaderboard sorts on those, not on upload rows.
func uploadersQuery(r *http.Request) (store.ListUploadersQuery, error) {
	v := r.URL.Query()

	limit, err := boundedInt(v.Get("limit"), defaultListLimit, 1, maxListLimit)
	if err != nil {
		return store.ListUploadersQuery{}, fmt.Errorf("limit %w", err)
	}
	offset, err := boundedInt(v.Get("offset"), 0, 0, 0)
	if err != nil {
		return store.ListUploadersQuery{}, fmt.Errorf("offset %w", err)
	}

	sort := v.Get("sort")
	if sort != "" && !store.ValidUploaderSort(sort) {
		return store.ListUploadersQuery{}, fmt.Errorf("sort must be file_count or file_size")
	}
	order := v.Get("order")
	if order != "" && !store.ValidOrder(order) {
		return store.ListUploadersQuery{}, fmt.Errorf("order must be asc or desc")
	}

	return store.ListUploadersQuery{Sort: sort, Order: order, Limit: limit, Offset: offset}, nil
}

type adminContentTypesResponse struct {
	ContentTypes []string `json:"content_types"`
}

// handleAdminContentTypes lists the distinct content types across all uploads,
// to populate the admin file-type filter dropdown.
func (s *Server) handleAdminContentTypes(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}

	types, err := s.store.ContentTypes(r.Context())
	if err != nil {
		s.log.Error("admin content types", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list content types")
		return
	}
	if types == nil {
		types = []string{}
	}
	writeJSON(w, http.StatusOK, adminContentTypesResponse{ContentTypes: types})
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
