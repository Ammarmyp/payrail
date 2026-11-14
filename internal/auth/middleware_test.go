package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Ammarmyp/payrail/internal/auth"
	"github.com/Ammarmyp/payrail/internal/user"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRequireAuth_RejectsMissingBearer(t *testing.T) {
	t.Parallel()
	signer := auth.NewTokenSigner("test-secret-at-least-32-bytes-long!!", time.Minute)
	h := auth.RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	errObj := body["error"].(map[string]any)
	require.Equal(t, "unauthorized", errObj["code"])
}

func TestRequireAuth_AllowsValidToken(t *testing.T) {
	t.Parallel()
	signer := auth.NewTokenSigner("test-secret-at-least-32-bytes-long!!", time.Minute)
	id := uuid.New()
	token, err := signer.SignAccess(id, user.RoleUser)
	require.NoError(t, err)

	var gotID uuid.UUID
	var gotRole user.Role
	h := auth.RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		gotID, ok = auth.UserIDFromContext(r.Context())
		require.True(t, ok)
		gotRole, ok = auth.RoleFromContext(r.Context())
		require.True(t, ok)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, id, gotID)
	require.Equal(t, user.RoleUser, gotRole)
}

func TestRequireRole_ForbiddenForUser(t *testing.T) {
	t.Parallel()
	signer := auth.NewTokenSigner("test-secret-at-least-32-bytes-long!!", time.Minute)
	token, err := signer.SignAccess(uuid.New(), user.RoleUser)
	require.NoError(t, err)

	h := auth.RequireAuth(signer)(auth.RequireRole(user.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	errObj := body["error"].(map[string]any)
	require.Equal(t, "forbidden", errObj["code"])
}
