package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/hivecom/orbit-depot/internal/auth"
	"github.com/hivecom/orbit-depot/internal/config"
	"github.com/hivecom/orbit-depot/internal/quota"
	"github.com/hivecom/orbit-depot/internal/store"
	"github.com/hivecom/orbit-depot/internal/store/sqlite"
)

func quotaServer(st *sqlite.Store, a auth.Authenticator, q quota.Enforcer) *Server {
	cfg := &config.Config{Depot: config.Depot{Driver: "fs"}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, log, Deps{Auth: a, Store: st, Quota: q})
}

func recordBytes(t *testing.T, st *sqlite.Store, account string, size int64) {
	t.Helper()
	err := st.RecordUpload(context.Background(), store.Upload{
		ObjectKey:       "uploads/" + account + "/" + time.Now().Format("150405.000000000") + "/f",
		UploaderAccount: account,
		UploaderIssuer:  "iss",
		FileSize:        size,
		ContentType:     "image/png",
		UploadedAt:      time.Now(),
	})
	if err != nil {
		t.Fatalf("RecordUpload: %v", err)
	}
}

func TestQuotaReportsUsageAndLimit(t *testing.T) {
	st := keysStore(t)
	recordBytes(t, st, "user-1", 100)
	recordBytes(t, st, "user-1", 250)

	q := quota.New(st, 1000, nil)
	s := quotaServer(st, fixedAuth{oidcID("user-1")}, q)

	rec := do(t, s, http.MethodGet, "/quota")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /quota = %d", rec.Code)
	}
	var got quotaResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Used != 350 || got.Limit != 1000 || got.Unlimited {
		t.Errorf("quota = %+v, want used=350 limit=1000 unlimited=false", got)
	}
}

func TestQuotaOverrideAndUnlimited(t *testing.T) {
	st := keysStore(t)

	// Override raises this account's limit.
	q := quota.New(st, 1000, map[string]int64{"vip": 5000})
	rec := do(t, quotaServer(st, fixedAuth{oidcID("vip")}, q), http.MethodGet, "/quota")
	var got quotaResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Limit != 5000 {
		t.Errorf("override limit = %d, want 5000", got.Limit)
	}

	// A zero default means unlimited.
	q0 := quota.New(st, 0, nil)
	rec = do(t, quotaServer(st, fixedAuth{oidcID("u")}, q0), http.MethodGet, "/quota")
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if !got.Unlimited || got.Limit != 0 {
		t.Errorf("unlimited quota = %+v, want unlimited=true limit=0", got)
	}
}

func TestQuotaRequiresIdentity(t *testing.T) {
	st := keysStore(t)
	s := quotaServer(st, auth.Anonymous(), quota.New(st, 1000, nil))
	if rec := do(t, s, http.MethodGet, "/quota"); rec.Code != http.StatusForbidden {
		t.Errorf("anonymous GET /quota = %d, want 403", rec.Code)
	}
}
