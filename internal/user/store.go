package user

import (
	"context"

	"github.com/google/uuid"
)

type Store interface {
	Create(ctx context.Context, email, passwordHash string, role Role) (User, error)
	FindByEmail(ctx context.Context, email string) (User, error)
	FindByID(ctx context.Context, id uuid.UUID) (User, error)
}
