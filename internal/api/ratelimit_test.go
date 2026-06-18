package api

import (
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/hivecom/orbit-depot/internal/auth"
	"github.com/hivecom/orbit-depot/internal/config"
	"github.com/hivecom/orbit-depot/internal/place"
	"github.com/hivecom/orbit-depot/internal/ratelimit"
	"github.com/hivecom/orbit-depot/internal/storage/fs"
)

// Presign requests from one IP are throttled to the configured per-IP rate.
func TestPresignRateLimitedPerIP(t *testing.T) {
	driver, err := fs.New(t.TempDir(), "http://depot.test")
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	reg, err := place.New(map[string]place.Definition{"uploads": {}}, "uploads", 100<<20)
	if err != nil {
		t.Fatalf("place.New: %v", err)
	}
	cfg := &config.Config{Depot: config.Depot{
		Driver: "fs",
		Limits: config.Limits{RateLimitPerIP: config.Rate{Count: 2, Window: time.Minute}},
	}}
	lim := ratelimit.NewMemory()
	defer lim.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(cfg, log, Deps{Driver: driver, Auth: auth.Anonymous(), Places: reg, Limiter: lim})

	body := `{"filename":"f.png","size":5,"content_type":"image/png"}`
	for i := range 2 {
		if rec := postJSON(t, s, "/upload/presign", body); rec.Code != http.StatusOK {
			t.Fatalf("presign %d = %d, want 200", i, rec.Code)
		}
	}
	if rec := postJSON(t, s, "/upload/presign", body); rec.Code != http.StatusTooManyRequests {
		t.Errorf("third presign = %d, want 429", rec.Code)
	}
}
