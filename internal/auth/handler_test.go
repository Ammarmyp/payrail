package auth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Ammarmyp/payrail/internal/auth"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func newTestRouter(t *testing.T) (*chi.Mux, *auth.Handler) {
	t.Helper()
	users := newMemUserStore()
	refresh := newMemRefreshStore()
	signer := auth.NewTokenSigner("test-secret-at-least-32-bytes-long!!", 15*time.Minute)
	svc := auth.NewService(users, refresh, signer, 7*24*time.Hour, bcrypt.MinCost)
	h := auth.NewHandler(svc, "development")

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Route("/v1/auth", func(r chi.Router) {
		h.Routes(r)
	})
	r.With(auth.RequireAuth(signer)).Get("/v1/me", h.Me)
	return r, h
}

func TestLogin_SetsRefreshCookie(t *testing.T) {
	t.Parallel()
	r, _ := newTestRouter(t)

	body := bytes.NewBufferString(`{"email":"cookie@example.com","password":"password1"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/signup", body)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	cookies := rec.Result().Cookies()
	var refresh *http.Cookie
	for _, c := range cookies {
		if c.Name == "refresh_token" {
			refresh = c
			break
		}
	}
	require.NotNil(t, refresh)
	require.True(t, refresh.HttpOnly)
	require.Equal(t, "/v1/auth", refresh.Path)
	require.False(t, refresh.Secure) // development

	var resp map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotEmpty(t, resp["access_token"])
	_, hasRefreshInBody := resp["refresh_token"]
	require.False(t, hasRefreshInBody)
}

func TestMe_RequiresAuth(t *testing.T) {
	t.Parallel()
	r, _ := newTestRouter(t)

	signupBody := bytes.NewBufferString(`{"email":"me@example.com","password":"password1"}`)
	signupReq := httptest.NewRequest(http.MethodPost, "/v1/auth/signup", signupBody)
	signupRec := httptest.NewRecorder()
	r.ServeHTTP(signupRec, signupReq)
	require.Equal(t, http.StatusCreated, signupRec.Code)

	var signupResp struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(signupRec.Body).Decode(&signupResp))

	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+signupResp.AccessToken)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var me map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&me))
	require.Equal(t, "me@example.com", me["email"])
	require.Equal(t, "user", me["role"])
	_, hasHash := me["password_hash"]
	require.False(t, hasHash)
}

func TestLogout_ClearsRefreshCookie(t *testing.T) {
	t.Parallel()
	r, _ := newTestRouter(t)

	signupBody := bytes.NewBufferString(`{"email":"logout@example.com","password":"password1"}`)
	signupReq := httptest.NewRequest(http.MethodPost, "/v1/auth/signup", signupBody)
	signupRec := httptest.NewRecorder()
	r.ServeHTTP(signupRec, signupReq)
	require.Equal(t, http.StatusCreated, signupRec.Code)

	var cookie *http.Cookie
	for _, c := range signupRec.Result().Cookies() {
		if c.Name == "refresh_token" {
			cookie = c
			break
		}
	}
	require.NotNil(t, cookie)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)

	var cleared *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "refresh_token" {
			cleared = c
			break
		}
	}
	require.NotNil(t, cleared)
	require.Equal(t, -1, cleared.MaxAge)

	refreshReq := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", nil)
	refreshReq.AddCookie(cookie)
	refreshRec := httptest.NewRecorder()
	r.ServeHTTP(refreshRec, refreshReq)
	require.Equal(t, http.StatusUnauthorized, refreshRec.Code)
}

func TestRefresh_UsesCookie(t *testing.T) {
	t.Parallel()
	r, _ := newTestRouter(t)

	signupBody := bytes.NewBufferString(`{"email":"refresh@example.com","password":"password1"}`)
	signupReq := httptest.NewRequest(http.MethodPost, "/v1/auth/signup", signupBody)
	signupRec := httptest.NewRecorder()
	r.ServeHTTP(signupRec, signupReq)
	require.Equal(t, http.StatusCreated, signupRec.Code)

	var cookie *http.Cookie
	for _, c := range signupRec.Result().Cookies() {
		if c.Name == "refresh_token" {
			cookie = c
			break
		}
	}
	require.NotNil(t, cookie)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotEmpty(t, resp["access_token"])
}
