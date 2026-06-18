package api

import "net/http"

// withCORS wraps next with cross-origin handling for the configured origins. It
// answers preflight OPTIONS requests and sets the response headers a browser
// needs to call Depot from another origin (the web client / Hivecom website).
//
// With no origins configured it is a pass-through: CLI and API-key callers are
// not browsers and need none of this. Credentials (cookies) are never enabled -
// Depot authenticates with a Bearer token, not cookies - so "*" is safe.
func withCORS(next http.Handler, origins []string) http.Handler {
	if len(origins) == 0 {
		return next
	}

	allowAll := false
	allowed := make(map[string]bool, len(origins))
	for _, o := range origins {
		if o == "*" {
			allowAll = true
		}
		allowed[o] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (allowAll || allowed[origin]) {
			if allowAll {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				// Echo the specific origin and vary on it, so a shared cache
				// never serves one origin's allowance to another.
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")
		}

		// A browser preflight is an OPTIONS carrying an Origin; answer it here
		// rather than letting it fall through to a 405 from the mux. When the
		// origin is not allowed no ACAO header was set, so the browser still
		// blocks the real request.
		if r.Method == http.MethodOptions && origin != "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
