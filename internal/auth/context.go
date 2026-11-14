package auth

import (
	"context"

	"github.com/Ammarmyp/payrail/internal/user"
	"github.com/google/uuid"
)

type ctxKey int

const (
	userIDKey ctxKey = iota
	roleKey
)

func ContextWithIdentity(ctx context.Context, userID uuid.UUID, role user.Role) context.Context {
	ctx = context.WithValue(ctx, userIDKey, userID)
	ctx = context.WithValue(ctx, roleKey, role)
	return ctx
}

func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

func RoleFromContext(ctx context.Context) (user.Role, bool) {
	role, ok := ctx.Value(roleKey).(user.Role)
	return role, ok
}
