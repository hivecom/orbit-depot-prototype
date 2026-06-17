package fs

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// UploadHandler receives proxied PUTs. It verifies the signed capability from
// the presign step, enforces the constraints baked into it, and writes the
// bytes to disk atomically (temp file + rename) so a failed transfer never
// leaves a partial object visible.
func (d *Driver) UploadHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("key")

		c, err := d.verifyUpload(key, r.URL.Query())
		if err != nil {
			status := http.StatusForbidden
			if err == errExpired {
				status = http.StatusGone
			}
			http.Error(w, err.Error(), status)
			return
		}

		if c.contentType != "" && r.Header.Get("Content-Type") != c.contentType {
			http.Error(w, "content-type does not match the presigned upload", http.StatusUnsupportedMediaType)
			return
		}
		if c.maxSize > 0 && r.ContentLength > c.maxSize {
			http.Error(w, "file exceeds the presigned size limit", http.StatusRequestEntityTooLarge)
			return
		}

		dst, err := d.diskPath(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}

		tmp, err := os.CreateTemp(filepath.Dir(dst), ".upload-*")
		if err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		tmpName := tmp.Name()
		// Best-effort cleanup; harmless once the rename has consumed tmp.
		defer os.Remove(tmpName)

		// Cap the copy one byte past the limit so an over-size body (which may
		// lie about Content-Length) is caught mid-stream.
		body := io.Reader(r.Body)
		if c.maxSize > 0 {
			body = io.LimitReader(r.Body, c.maxSize+1)
		}
		n, err := io.Copy(tmp, body)
		tmp.Close()
		if err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		if c.maxSize > 0 && n > c.maxSize {
			http.Error(w, "file exceeds the presigned size limit", http.StatusRequestEntityTooLarge)
			return
		}

		if err := os.Rename(tmpName, dst); err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
}

// DownloadHandler serves objects from disk. Recipient-scoping is a NEXT
// capability; for now objects are served to anyone with the URL, matching the
// public-bucket posture of the s3 driver.
func (d *Driver) DownloadHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dst, err := d.diskPath(r.PathValue("key"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f, err := os.Open(dst)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		defer f.Close()

		info, err := f.Stat()
		if err != nil || info.IsDir() {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.ServeContent(w, r, filepath.Base(dst), info.ModTime(), f)
	})
}
