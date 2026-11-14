package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type RefreshStore interface {
	Create(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) (RefreshToken, error)
	FindByHash(ctx context.Context, tokenHash []byte) (RefreshToken, error)
	Revoke(ctx context.Context, id uuid.UUID) error
}
