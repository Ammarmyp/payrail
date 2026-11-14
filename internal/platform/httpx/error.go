package httpx

import (
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

func WriteAPIError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	reqID := middleware.GetReqID(r.Context())
	WriteJSON(w, status, errorBody{
		Error: errorDetail{
			Code:      code,
			Message:   message,
			RequestID: reqID,
		},
	})
}
