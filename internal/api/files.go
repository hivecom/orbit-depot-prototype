package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/hivecom/orbit-depot/internal/store"
)

const (
	defaultListLimit = 50
	maxListLimit     = 200
)

type fileItem struct {
	ObjectKey        string    `json:"object_key"`
	URL              string    `json:"url"`
	Size             int64     `json:"size"`
	ContentType      string    `json:"content_type"`
	OriginalFilename string    `json:"original_filename"`
	UploadedAt       time.Time `json:"uploaded_at"`
}

type listFilesResponse struct {
	Files []fileItem `json:"files"`
	Total int        `json:"total"`
}

// handleListFiles returns a page of the caller's own uploads. Listing needs an
// identity, so anonymous requests are rejected; the query is forced to the
// caller's subject/issuer so a user only ever sees their own rows.
func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil || s.store == nil || s.driver == nil {
		writeError(w, http.StatusNotImplemented, "file listing is not implemented yet")
		return
	}

	id, err := s.auth.Authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return
	}
	if id.Anonymous {
		writeError(w, http.StatusForbidden, "listing requires an authenticated identity")
		return
	}

	q, err := listQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	q.Account = id.Subject
	q.Issuer = id.Issuer

	uploads, total, err := s.store.ListUploads(r.Context(), q)
	if err != nil {
		s.log.Error("list uploads", "error", err, "account", id.Subject)
		writeError(w, http.StatusInternalServerError, "could not list files")
		return
	}

	items, err := s.fileItems(r.Context(), uploads)
	if err != nil {
		s.log.Error("resolve download", "error", err, "account", id.Subject)
		writeError(w, http.StatusInternalServerError, "could not resolve download URL")
		return
	}

	writeJSON(w, http.StatusOK, listFilesResponse{Files: items, Total: total})
}

// fileItems builds the response rows, resolving each download URL through the
// driver the same way handleUpload does (the driver owns URL construction).
func (s *Server) fileItems(ctx context.Context, uploads []store.Upload) ([]fileItem, error) {
	items := make([]fileItem, 0, len(uploads))
	for _, u := range uploads {
		url, err := s.driver.ResolveDownload(ctx, u.ObjectKey)
		if err != nil {
			return nil, err
		}
		items = append(items, fileItem{
			ObjectKey:        u.ObjectKey,
			URL:              url,
			Size:             u.FileSize,
			ContentType:      u.ContentType,
			OriginalFilename: u.OriginalFilename,
			UploadedAt:       u.UploadedAt,
		})
	}
	return items, nil
}

// listQuery parses and validates the shared listing params (limit, offset, sort,
// order, q). Owner and content-type filters are layered on by the caller. An
// unknown sort/order or a non-numeric limit/offset is rejected, not defaulted;
// only an omitted value falls back to the default.
func listQuery(r *http.Request) (store.ListUploadsQuery, error) {
	v := r.URL.Query()

	limit, err := boundedInt(v.Get("limit"), defaultListLimit, 1, maxListLimit)
	if err != nil {
		return store.ListUploadsQuery{}, fmt.Errorf("limit %w", err)
	}
	offset, err := boundedInt(v.Get("offset"), 0, 0, 0)
	if err != nil {
		return store.ListUploadsQuery{}, fmt.Errorf("offset %w", err)
	}

	sort := v.Get("sort")
	if sort != "" && !store.ValidSort(sort) {
		return store.ListUploadsQuery{}, fmt.Errorf("sort must be uploaded_at or file_size")
	}
	order := v.Get("order")
	if order != "" && !store.ValidOrder(order) {
		return store.ListUploadsQuery{}, fmt.Errorf("order must be asc or desc")
	}

	return store.ListUploadsQuery{
		Search: v.Get("q"),
		Sort:   sort,
		Order:  order,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// boundedInt parses q and clamps it to [min, max], returning def when q is
// omitted. A non-numeric q is an error: the request must conform. The max <= 0
// means no upper bound; clamping to the documented max is not an error.
func boundedInt(q string, def, min, max int) (int, error) {
	if q == "" {
		return def, nil
	}
	n, err := strconv.Atoi(q)
	if err != nil {
		return 0, fmt.Errorf("must be an integer")
	}
	if n < min {
		n = min
	}
	if max > 0 && n > max {
		n = max
	}
	return n, nil
}
