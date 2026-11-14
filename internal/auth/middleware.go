package auth

import (
	"net/http"
	"strings"

	"github.com/Ammarmyp/payrail/internal/user"
)

func RequireAuth(signer *TokenSigner) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				writeError(w, r, ErrUnauthorized)
				return
			}
			token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
			claims, err := signer.ParseAccess(token)
			if err != nil {
				writeError(w, r, ErrUnauthorized)
				return
			}
			ctx := ContextWithIdentity(r.Context(), claims.UserID, claims.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireRole(roles ...user.Role) func(http.Handler) http.Handler {
	allowed := make(map[user.Role]struct{}, len(roles))
	for _, role := range roles {
		allowed[role] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := RoleFromContext(r.Context())
			if !ok {
				writeError(w, r, ErrUnauthorized)
				return
			}
			if _, ok := allowed[role]; !ok {
				writeError(w, r, ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
