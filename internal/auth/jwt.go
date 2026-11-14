package auth

import (
	"fmt"
	"time"

	"github.com/Ammarmyp/payrail/internal/user"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AccessClaims struct {
	UserID    uuid.UUID
	Role      user.Role
	ExpiresAt time.Time
}

type TokenSigner struct {
	secret []byte
	ttl    time.Duration
}

func NewTokenSigner(secret string, ttl time.Duration) *TokenSigner {
	return &TokenSigner{secret: []byte(secret), ttl: ttl}
}

type jwtClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func (s *TokenSigner) SignAccess(userID uuid.UUID, role user.Role) (string, error) {
	now := time.Now().UTC()
	claims := jwtClaims{
		Role: string(role),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return signed, nil
}

func (s *TokenSigner) ParseAccess(tokenString string) (AccessClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwtClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return AccessClaims{}, fmt.Errorf("parse access token: %w", err)
	}

	claims, ok := token.Claims.(*jwtClaims)
	if !ok || !token.Valid {
		return AccessClaims{}, fmt.Errorf("invalid access token")
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return AccessClaims{}, fmt.Errorf("invalid subject: %w", err)
	}

	var exp time.Time
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}

	return AccessClaims{
		UserID:    userID,
		Role:      user.Role(claims.Role),
		ExpiresAt: exp,
	}, nil
}

func (s *TokenSigner) AccessTTL() time.Duration {
	return s.ttl
}
