package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

func TestReadyz(t *testing.T) {
	tests := []struct {
		name   string
		checks map[string]Pinger
		want   int
	}{
		{"all up", map[string]Pinger{"db": fakePinger{}}, http.StatusOK},
		{"one down", map[string]Pinger{"db": fakePinger{errors.New("boom")}}, http.StatusServiceUnavailable},
		{"no checks", map[string]Pinger{}, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil)

			Readyz(tt.checks).ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("Got %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)

	Healthz().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusOK)
	}
}
