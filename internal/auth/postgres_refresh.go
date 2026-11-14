package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRefreshStore struct {
	pool *pgxpool.Pool
}

func NewPostgresRefreshStore(pool *pgxpool.Pool) *PostgresRefreshStore {
	return &PostgresRefreshStore{pool: pool}
}

func (s *PostgresRefreshStore) Create(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) (RefreshToken, error) {
	const q = `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, user_id, token_hash, expires_at, revoked_at, created_at`

	var rt RefreshToken
	err := s.pool.QueryRow(ctx, q, userID, tokenHash, expiresAt).Scan(
		&rt.ID, &rt.UserID, &rt.TokenHash, &rt.ExpiresAt, &rt.RevokedAt, &rt.CreatedAt,
	)
	if err != nil {
		return RefreshToken{}, fmt.Errorf("create refresh token: %w", err)
	}
	return rt, nil
}

func (s *PostgresRefreshStore) FindByHash(ctx context.Context, tokenHash []byte) (RefreshToken, error) {
	const q = `
		SELECT id, user_id, token_hash, expires_at, revoked_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1`

	var rt RefreshToken
	err := s.pool.QueryRow(ctx, q, tokenHash).Scan(
		&rt.ID, &rt.UserID, &rt.TokenHash, &rt.ExpiresAt, &rt.RevokedAt, &rt.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	if err != nil {
		return RefreshToken{}, fmt.Errorf("find refresh token: %w", err)
	}
	return rt, nil
}

func (s *PostgresRefreshStore) Revoke(ctx context.Context, id uuid.UUID) error {
	const q = `
		UPDATE refresh_tokens
		SET revoked_at = now()
		WHERE id = $1 AND revoked_at IS NULL`

	tag, err := s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
