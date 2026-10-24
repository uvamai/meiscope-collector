package platform

import (
	"encoding/json"
	"net/http"
)

// Health is the /healthz response body (schema Health in api/collector.yaml).
type Health struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// HealthHandler answers GET /healthz with the build information.
func HealthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Health{Status: "ok", Version: Version, Commit: Commit})
	})
	return mux
}
