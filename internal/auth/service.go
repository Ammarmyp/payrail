package auth

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Ammarmyp/payrail/internal/user"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const minPasswordLen = 8

type Session struct {
	User         user.User
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	RefreshTTL   time.Duration
}

type Service struct {
	users      user.Store
	refresh    RefreshStore
	signer     *TokenSigner
	refreshTTL time.Duration
	bcryptCost int
}

func NewService(users user.Store, refresh RefreshStore, signer *TokenSigner, refreshTTL time.Duration, bcryptCost int) *Service {
	return &Service{
		users:      users,
		refresh:    refresh,
		signer:     signer,
		refreshTTL: refreshTTL,
		bcryptCost: bcryptCost,
	}
}

func (s *Service) Signup(ctx context.Context, email, password string) (Session, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return Session{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if err := validatePassword(password); err != nil {
		return Session{}, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	if err != nil {
		return Session{}, fmt.Errorf("hash password: %w", err)
	}

	u, err := s.users.Create(ctx, email, string(hash), user.RoleUser)
	if err != nil {
		return Session{}, err
	}

	return s.issueSession(ctx, u)
}

func (s *Service) Login(ctx context.Context, email, password string) (Session, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return Session{}, ErrInvalidCredentials
	}

	u, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return Session{}, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return Session{}, ErrInvalidCredentials
	}

	return s.issueSession(ctx, u)
}

func (s *Service) Refresh(ctx context.Context, rawRefresh string) (Session, error) {
	rt, err := s.lookupActiveRefresh(ctx, rawRefresh)
	if err != nil {
		return Session{}, err
	}

	if err := s.refresh.Revoke(ctx, rt.ID); err != nil {
		return Session{}, err
	}

	u, err := s.users.FindByID(ctx, rt.UserID)
	if err != nil {
		return Session{}, ErrUnauthorized
	}

	return s.issueSession(ctx, u)
}

func (s *Service) Logout(ctx context.Context, rawRefresh string) error {
	rt, err := s.lookupActiveRefresh(ctx, rawRefresh)
	if err != nil {
		// Idempotent logout: missing/invalid refresh is already logged out.
		return nil
	}
	return s.refresh.Revoke(ctx, rt.ID)
}

func (s *Service) Me(ctx context.Context, userID uuid.UUID) (user.User, error) {
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return user.User{}, err
	}
	u.PasswordHash = ""
	return u, nil
}

func (s *Service) issueSession(ctx context.Context, u user.User) (Session, error) {
	access, err := s.signer.SignAccess(u.ID, u.Role)
	if err != nil {
		return Session{}, err
	}

	raw, err := newRawRefreshToken()
	if err != nil {
		return Session{}, err
	}

	expiresAt := time.Now().UTC().Add(s.refreshTTL)
	if _, err := s.refresh.Create(ctx, u.ID, HashRefreshToken(raw), expiresAt); err != nil {
		return Session{}, err
	}

	u.PasswordHash = ""
	return Session{
		User:         u,
		AccessToken:  access,
		RefreshToken: raw,
		ExpiresIn:    int64(s.signer.AccessTTL() / time.Second),
		RefreshTTL:   s.refreshTTL,
	}, nil
}

func (s *Service) lookupActiveRefresh(ctx context.Context, rawRefresh string) (RefreshToken, error) {
	if rawRefresh == "" {
		return RefreshToken{}, ErrUnauthorized
	}

	rt, err := s.refresh.FindByHash(ctx, HashRefreshToken(rawRefresh))
	if err != nil {
		return RefreshToken{}, ErrUnauthorized
	}
	if rt.RevokedAt != nil {
		return RefreshToken{}, ErrUnauthorized
	}
	if time.Now().UTC().After(rt.ExpiresAt) {
		return RefreshToken{}, ErrUnauthorized
	}
	return rt, nil
}

func normalizeEmail(email string) (string, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return "", fmt.Errorf("email required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return "", fmt.Errorf("invalid email")
	}
	return email, nil
}

func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < minPasswordLen {
		return fmt.Errorf("%w: password must be at least %d characters", ErrValidation, minPasswordLen)
	}
	return nil
}
