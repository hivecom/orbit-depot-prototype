package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/hivecom/orbit-depot/internal/place"
	"github.com/hivecom/orbit-depot/internal/quota"
	"github.com/hivecom/orbit-depot/internal/storage"
	"github.com/hivecom/orbit-depot/internal/store"
)

// presignTTL is how long a presigned upload URL stays valid. The client
// presigns immediately before uploading, so a short window is plenty.
const presignTTL = 15 * time.Minute

// maxPresignBody bounds the presign request body; it is small JSON.
const maxPresignBody = 4 << 10

type presignRequest struct {
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	Place       string `json:"place"`
}

type presignResponse struct {
	UploadURL   string            `json:"upload_url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers,omitempty"`
	ObjectKey   string            `json:"object_key"`
	ExpiresIn   int               `json:"expires_in"`
	DownloadURL string            `json:"download_url"`
}

// handlePresign authenticates the caller, resolves the target place, validates
// the request against the place's policy, derives the object key from the
// verified identity, and returns a time-limited upload URL. The client never
// names the object key; placement is decided here.
func (s *Server) handlePresign(w http.ResponseWriter, r *http.Request) {
	if s.driver == nil || s.auth == nil || s.places == nil {
		writeError(w, http.StatusNotImplemented, "presign is not implemented yet")
		return
	}

	id, err := s.auth.Authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return
	}

	var req presignRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPresignBody))
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Filename == "" {
		writeError(w, http.StatusBadRequest, "filename is required")
		return
	}

	pl, err := s.places.Resolve(req.Place)
	if err != nil {
		writeError(w, placeErrorStatus(err), err.Error())
		return
	}

	preq := place.Request{Filename: req.Filename, Size: req.Size, ContentType: req.ContentType}
	if err := pl.Validate(preq, id.Anonymous); err != nil {
		writeError(w, placeErrorStatus(err), err.Error())
		return
	}

	// Quota applies only to identified callers; anonymous uploads cannot be
	// attributed to a user. An over-quota result is the caller's fault (413); a
	// failed usage read is ours (500).
	if !id.Anonymous {
		if err := s.quota.Check(r.Context(), id.Subject, id.Issuer, req.Size); err != nil {
			if errors.Is(err, quota.ErrExceeded) {
				writeError(w, http.StatusRequestEntityTooLarge, "quota exceeded")
				return
			}
			s.log.Error("quota check", "error", err, "account", id.Subject)
			writeError(w, http.StatusInternalServerError, "could not check quota")
			return
		}
	}

	key, err := pl.DeriveKey(id.Subject, id.Issuer, id.Anonymous, preq)
	if err != nil {
		writeError(w, placeErrorStatus(err), err.Error())
		return
	}

	target, err := s.driver.PresignUpload(r.Context(), key, storage.Constraints{
		ContentType: req.ContentType,
		MaxSize:     req.Size,
		Expiry:      presignTTL,
	})
	if err != nil {
		s.log.Error("presign upload", "error", err, "key", key)
		writeError(w, http.StatusInternalServerError, "could not presign upload")
		return
	}

	download, err := s.driver.ResolveDownload(r.Context(), key)
	if err != nil {
		s.log.Error("resolve download", "error", err, "key", key)
		writeError(w, http.StatusInternalServerError, "could not resolve download URL")
		return
	}

	// Record the upload at presign time when a metadata store is present. The
	// presigned URL constrains the actual upload, so the row is a reliable
	// record of intent even before the bytes land.
	if s.store != nil {
		rec := store.Upload{
			ObjectKey:        target.ObjectKey,
			UploaderAccount:  id.Subject,
			UploaderIssuer:   id.Issuer,
			FileSize:         req.Size,
			ContentType:      req.ContentType,
			OriginalFilename: req.Filename,
			UploadedAt:       time.Now(),
		}
		if err := s.store.RecordUpload(r.Context(), rec); err != nil {
			s.log.Error("record upload", "error", err, "key", key)
			writeError(w, http.StatusInternalServerError, "could not record upload")
			return
		}
	}

	writeJSON(w, http.StatusOK, presignResponse{
		UploadURL:   target.URL,
		Method:      target.Method,
		Headers:     target.Headers,
		ObjectKey:   target.ObjectKey,
		ExpiresIn:   target.ExpiresIn,
		DownloadURL: download,
	})
}

// One-shot upload tuning. oneshotMemory bounds how much of a multipart body is
// buffered in memory before spilling to a temp file; oneshotOverhead is slack
// over max_file_size for multipart framing in the coarse body guard.
const (
	oneshotMemory   = 8 << 20
	oneshotOverhead = 1 << 20
)

type oneshotResponse struct {
	ObjectKey   string `json:"object_key"`
	URL         string `json:"url"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type,omitempty"`
}

// handleUpload is the one-shot endpoint for tools that cannot run the presign
// dance (ShareX, cURL): it accepts the file bytes as multipart/form-data,
// authenticates, validates against the target place, writes the bytes through
// the driver, records metadata, and returns the final URL. It proxies bytes even
// under the s3 driver, so it is meant to be rate-limited harder than presign.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if s.driver == nil || s.auth == nil || s.places == nil {
		writeError(w, http.StatusNotImplemented, "one-shot upload is not implemented yet")
		return
	}
	writer, ok := s.driver.(storage.ObjectWriter)
	if !ok {
		writeError(w, http.StatusNotImplemented, "the active storage driver does not support one-shot upload")
		return
	}

	id, err := s.auth.Authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return
	}

	// Coarse guard before multipart is spooled to disk; the driver enforces the
	// exact per-file limit during the write.
	if maxBytes := int64(s.cfg.Depot.Limits.MaxFileSize); maxBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes+oneshotOverhead)
	}
	if err := r.ParseMultipartForm(oneshotMemory); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "upload exceeds the maximum size")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid multipart upload")
		return
	}
	defer r.MultipartForm.RemoveAll()

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing file field")
		return
	}
	defer file.Close()

	pl, err := s.places.Resolve(r.FormValue("place"))
	if err != nil {
		writeError(w, placeErrorStatus(err), err.Error())
		return
	}

	contentType := header.Header.Get("Content-Type")
	preq := place.Request{Filename: header.Filename, Size: header.Size, ContentType: contentType}
	if err := pl.Validate(preq, id.Anonymous); err != nil {
		writeError(w, placeErrorStatus(err), err.Error())
		return
	}

	if !id.Anonymous {
		if err := s.quota.Check(r.Context(), id.Subject, id.Issuer, header.Size); err != nil {
			if errors.Is(err, quota.ErrExceeded) {
				writeError(w, http.StatusRequestEntityTooLarge, "quota exceeded")
				return
			}
			s.log.Error("quota check", "error", err, "account", id.Subject)
			writeError(w, http.StatusInternalServerError, "could not check quota")
			return
		}
	}

	key, err := pl.DeriveKey(id.Subject, id.Issuer, id.Anonymous, preq)
	if err != nil {
		writeError(w, placeErrorStatus(err), err.Error())
		return
	}

	n, err := writer.PutObject(r.Context(), key, storage.Constraints{ContentType: contentType, MaxSize: header.Size}, file)
	if err != nil {
		if errors.Is(err, storage.ErrTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "file exceeds the size limit")
			return
		}
		s.log.Error("put object", "error", err, "key", key)
		writeError(w, http.StatusInternalServerError, "could not store upload")
		return
	}

	if s.store != nil {
		rec := store.Upload{
			ObjectKey:        key,
			UploaderAccount:  id.Subject,
			UploaderIssuer:   id.Issuer,
			FileSize:         n,
			ContentType:      contentType,
			OriginalFilename: header.Filename,
			UploadedAt:       time.Now(),
		}
		if err := s.store.RecordUpload(r.Context(), rec); err != nil {
			s.log.Error("record upload", "error", err, "key", key)
			writeError(w, http.StatusInternalServerError, "could not record upload")
			return
		}
	}

	download, err := s.driver.ResolveDownload(r.Context(), key)
	if err != nil {
		s.log.Error("resolve download", "error", err, "key", key)
		writeError(w, http.StatusInternalServerError, "could not resolve download URL")
		return
	}

	writeJSON(w, http.StatusCreated, oneshotResponse{
		ObjectKey:   key,
		URL:         download,
		Size:        n,
		ContentType: contentType,
	})
}

// placeErrorStatus maps a place policy error to an HTTP status code.
func placeErrorStatus(err error) int {
	switch {
	case errors.Is(err, place.ErrUnknownPlace):
		return http.StatusNotFound
	case errors.Is(err, place.ErrNoPlaceSpecified):
		return http.StatusBadRequest
	case errors.Is(err, place.ErrIdentityRequired):
		return http.StatusForbidden
	case errors.Is(err, place.ErrTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, place.ErrMIMENotAllowed):
		return http.StatusUnsupportedMediaType
	default:
		return http.StatusBadRequest
	}
}
