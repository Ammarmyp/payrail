package auth_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Ammarmyp/payrail/internal/auth"
	"github.com/Ammarmyp/payrail/internal/user"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type memUserStore struct {
	mu    sync.Mutex
	byID  map[uuid.UUID]user.User
	email map[string]uuid.UUID
}

func newMemUserStore() *memUserStore {
	return &memUserStore{
		byID:  make(map[uuid.UUID]user.User),
		email: make(map[string]uuid.UUID),
	}
}

func (s *memUserStore) Create(_ context.Context, email, passwordHash string, role user.Role) (user.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.email[email]; ok {
		return user.User{}, user.ErrEmailTaken
	}
	u := user.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now().UTC(),
	}
	s.byID[u.ID] = u
	s.email[email] = u.ID
	return u, nil
}

func (s *memUserStore) FindByEmail(_ context.Context, email string) (user.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.email[email]
	if !ok {
		return user.User{}, user.ErrNotFound
	}
	return s.byID[id], nil
}

func (s *memUserStore) FindByID(_ context.Context, id uuid.UUID) (user.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return user.User{}, user.ErrNotFound
	}
	return u, nil
}

type memRefreshStore struct {
	mu   sync.Mutex
	byID map[uuid.UUID]auth.RefreshToken
	hash map[string]uuid.UUID
}

func newMemRefreshStore() *memRefreshStore {
	return &memRefreshStore{
		byID: make(map[uuid.UUID]auth.RefreshToken),
		hash: make(map[string]uuid.UUID),
	}
}

func (s *memRefreshStore) Create(_ context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) (auth.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt := auth.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: append([]byte(nil), tokenHash...),
		ExpiresAt: expiresAt,
		CreatedAt: time.Now().UTC(),
	}
	s.byID[rt.ID] = rt
	s.hash[string(tokenHash)] = rt.ID
	return rt, nil
}

func (s *memRefreshStore) FindByHash(_ context.Context, tokenHash []byte) (auth.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.hash[string(tokenHash)]
	if !ok {
		return auth.RefreshToken{}, auth.ErrNotFound
	}
	return s.byID[id], nil
}

func (s *memRefreshStore) Revoke(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.byID[id]
	if !ok {
		return auth.ErrNotFound
	}
	now := time.Now().UTC()
	rt.RevokedAt = &now
	s.byID[id] = rt
	return nil
}

func testService(t *testing.T) (*auth.Service, *memUserStore, *memRefreshStore) {
	t.Helper()
	users := newMemUserStore()
	refresh := newMemRefreshStore()
	signer := auth.NewTokenSigner("test-secret-at-least-32-bytes-long!!", 15*time.Minute)
	svc := auth.NewService(users, refresh, signer, 7*24*time.Hour, bcrypt.MinCost)
	return svc, users, refresh
}

func TestSignup_CreatesUserAndTokens(t *testing.T) {
	t.Parallel()
	svc, users, _ := testService(t)

	session, err := svc.Signup(context.Background(), "a@example.com", "password1")
	require.NoError(t, err)
	require.Equal(t, "a@example.com", session.User.Email)
	require.Equal(t, user.RoleUser, session.User.Role)
	require.NotEmpty(t, session.AccessToken)
	require.NotEmpty(t, session.RefreshToken)
	require.Equal(t, int64(15*60), session.ExpiresIn)

	stored, err := users.FindByEmail(context.Background(), "a@example.com")
	require.NoError(t, err)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored.PasswordHash), []byte("password1")))
}

func TestSignup_RejectsDuplicateEmail(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	_, err := svc.Signup(context.Background(), "a@example.com", "password1")
	require.NoError(t, err)

	_, err = svc.Signup(context.Background(), "a@example.com", "password1")
	require.ErrorIs(t, err, user.ErrEmailTaken)
}

func TestSignup_RejectsShortPassword(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	_, err := svc.Signup(context.Background(), "a@example.com", "short")
	require.ErrorIs(t, err, auth.ErrValidation)
}

func TestLogin_IssuesTokens(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	_, err := svc.Signup(context.Background(), "b@example.com", "password1")
	require.NoError(t, err)

	session, err := svc.Login(context.Background(), "b@example.com", "password1")
	require.NoError(t, err)
	require.NotEmpty(t, session.AccessToken)
	require.NotEmpty(t, session.RefreshToken)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	_, err := svc.Signup(context.Background(), "c@example.com", "password1")
	require.NoError(t, err)

	_, err = svc.Login(context.Background(), "c@example.com", "wrong-password")
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)

	_, err = svc.Login(context.Background(), "missing@example.com", "password1")
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

func TestRefresh_RotatesToken(t *testing.T) {
	t.Parallel()
	svc, _, refresh := testService(t)
	created, err := svc.Signup(context.Background(), "d@example.com", "password1")
	require.NoError(t, err)

	next, err := svc.Refresh(context.Background(), created.RefreshToken)
	require.NoError(t, err)
	require.NotEmpty(t, next.AccessToken)
	require.NotEqual(t, created.RefreshToken, next.RefreshToken)

	oldHash := auth.HashRefreshToken(created.RefreshToken)
	old, err := refresh.FindByHash(context.Background(), oldHash)
	require.NoError(t, err)
	require.NotNil(t, old.RevokedAt)

	_, err = svc.Refresh(context.Background(), created.RefreshToken)
	require.ErrorIs(t, err, auth.ErrUnauthorized)
}

func TestLogout_RevokesRefresh(t *testing.T) {
	t.Parallel()
	svc, _, _ := testService(t)
	created, err := svc.Signup(context.Background(), "e@example.com", "password1")
	require.NoError(t, err)

	require.NoError(t, svc.Logout(context.Background(), created.RefreshToken))
	_, err = svc.Refresh(context.Background(), created.RefreshToken)
	require.ErrorIs(t, err, auth.ErrUnauthorized)
}
