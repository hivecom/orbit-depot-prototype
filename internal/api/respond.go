package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// writeJSON encodes v as a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encode response", "error", err)
	}
}

// errorBody is the consistent shape for error responses.
type errorBody struct {
	Error string `json:"error"`
}

// writeError sends a JSON error with the given status code.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}
