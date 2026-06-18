package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/hivecom/orbit-depot/internal/config"
)

// clientIP returns the caller's IP for rate-limit scoping. Behind a trusted
// reverse proxy (config opt-in) it reads the forwarded headers; otherwise it
// uses the direct connection, since forwarded headers are client-spoofable.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.Depot.TrustForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Leftmost entry is the original client (single trusted proxy).
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimit enforces rate for the given scope key. It returns true when the
// request may proceed; when the limit is exceeded it writes a 429 and returns
// false. It is a no-op when no limiter is wired or the rate is unset, and it
// fails open if the limiter backend errors - a throttling backend hiccup must
// not take uploads down.
func (s *Server) rateLimit(w http.ResponseWriter, r *http.Request, key string, rate config.Rate) bool {
	if s.limiter == nil || rate.Zero() {
		return true
	}
	ok, err := s.limiter.Allow(r.Context(), key, rate.Count, rate.Window)
	if err != nil {
		s.log.Error("rate limit check", "error", err, "key", key)
		return true
	}
	if !ok {
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return false
	}
	return true
}
