package auth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Ammarmyp/payrail/internal/platform/httpx"
)

const refreshCookieName = "refresh_token"

type Handler struct {
	svc *Service
	env string
}

func NewHandler(svc *Service, env string) *Handler {
	return &Handler{svc: svc, env: env}
}

type credentialsRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresIn   int64     `json:"expires_in"`
	User        userView  `json:"user"`
}

type userView struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (h *Handler) Routes(r chiRouter) {
	r.Post("/signup", h.Signup)
	r.Post("/login", h.Login)
	r.Post("/refresh", h.Refresh)
	r.Post("/logout", h.Logout)
}

// chiRouter is the subset of chi.Router used by auth routes.
type chiRouter interface {
	Post(pattern string, handlerFn http.HandlerFunc)
}

func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, ErrValidation)
		return
	}
	session, err := h.svc.Signup(r.Context(), req.Email, req.Password)
	if err != nil {
		writeError(w, r, err)
		return
	}
	h.writeSession(w, http.StatusCreated, session)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, ErrValidation)
		return
	}
	session, err := h.svc.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		writeError(w, r, err)
		return
	}
	h.writeSession(w, http.StatusOK, session)
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	raw, err := r.Cookie(refreshCookieName)
	if err != nil || raw.Value == "" {
		writeError(w, r, ErrUnauthorized)
		return
	}
	session, err := h.svc.Refresh(r.Context(), raw.Value)
	if err != nil {
		writeError(w, r, err)
		return
	}
	h.writeSession(w, http.StatusOK, session)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(refreshCookieName); err == nil {
		_ = h.svc.Logout(r.Context(), c.Value)
	}
	h.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, r, ErrUnauthorized)
		return
	}
	u, err := h.svc.Me(r.Context(), userID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, userView{
		ID:    u.ID.String(),
		Email: u.Email,
		Role:  string(u.Role),
	})
}

func (h *Handler) writeSession(w http.ResponseWriter, status int, session Session) {
	h.setRefreshCookie(w, session.RefreshToken, session.RefreshTTL)
	httpx.WriteJSON(w, status, tokenResponse{
		AccessToken: session.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   session.ExpiresIn,
		User: userView{
			ID:    session.User.ID.String(),
			Email: session.User.Email,
			Role:  string(session.User.Role),
		},
	})
}

func (h *Handler) setRefreshCookie(w http.ResponseWriter, raw string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    raw,
		Path:     "/v1/auth",
		HttpOnly: true,
		Secure:   h.env != "development",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func (h *Handler) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     "/v1/auth",
		HttpOnly: true,
		Secure:   h.env != "development",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
