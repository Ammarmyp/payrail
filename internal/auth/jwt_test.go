package auth_test

import (
	"testing"
	"time"

	"github.com/Ammarmyp/payrail/internal/auth"
	"github.com/Ammarmyp/payrail/internal/user"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestAccessToken_RoundTrip(t *testing.T) {
	t.Parallel()

	signer := auth.NewTokenSigner("test-secret-at-least-32-bytes-long!!", 15*time.Minute)
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	token, err := signer.SignAccess(id, user.RoleUser)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := signer.ParseAccess(token)
	require.NoError(t, err)
	require.Equal(t, id, claims.UserID)
	require.Equal(t, user.RoleUser, claims.Role)
	require.WithinDuration(t, time.Now().Add(15*time.Minute), claims.ExpiresAt, 2*time.Second)
}

func TestAccessToken_RejectsTampered(t *testing.T) {
	t.Parallel()

	signer := auth.NewTokenSigner("test-secret-at-least-32-bytes-long!!", 15*time.Minute)
	token, err := signer.SignAccess(uuid.New(), user.RoleAdmin)
	require.NoError(t, err)

	_, err = signer.ParseAccess(token + "x")
	require.Error(t, err)
}

func TestAccessToken_RejectsExpired(t *testing.T) {
	t.Parallel()

	signer := auth.NewTokenSigner("test-secret-at-least-32-bytes-long!!", -time.Minute)
	token, err := signer.SignAccess(uuid.New(), user.RoleUser)
	require.NoError(t, err)

	_, err = signer.ParseAccess(token)
	require.Error(t, err)
}
