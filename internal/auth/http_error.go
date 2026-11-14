package auth

import (
	"errors"
	"net/http"

	"github.com/Ammarmyp/payrail/internal/platform/httpx"
	"github.com/Ammarmyp/payrail/internal/user"
)

func writeError(w http.ResponseWriter, r *http.Request, err error) {
	code, status, message := mapError(err)
	httpx.WriteAPIError(w, r, status, code, message)
}

func mapError(err error) (code string, status int, message string) {
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return "invalid_credentials", http.StatusUnauthorized, "invalid email or password"
	case errors.Is(err, user.ErrEmailTaken):
		return "email_taken", http.StatusConflict, "email already registered"
	case errors.Is(err, ErrValidation):
		return "validation_error", http.StatusBadRequest, err.Error()
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrNotFound), errors.Is(err, user.ErrNotFound):
		return "unauthorized", http.StatusUnauthorized, "unauthorized"
	case errors.Is(err, ErrForbidden):
		return "forbidden", http.StatusForbidden, "forbidden"
	default:
		return "internal_error", http.StatusInternalServerError, "internal server error"
	}
}
