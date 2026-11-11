package httpx

import (
	"context"
	"net/http"
	"time"
)

type Pinger interface {
	Ping(ctx context.Context) error
}

func Healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"status": "OK"})
	}
}

func Readyz(checks map[string]Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		status, code := "ready", http.StatusOK
		results := make(map[string]string, len(checks))

		for name, c := range checks {
			if err := c.Ping(ctx); err != nil {
				results[name] = "down"
				status, code = "not_ready", http.StatusServiceUnavailable
				continue
			}

			results[name] = "up"
		}

		WriteJSON(w, code, map[string]any{"status": status, "checks": results})
	}
}
