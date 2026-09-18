package repository

import (
	"context"
	"testing"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fake repositories for unit testing (matching the pattern in service_test.go)

type fakeUserRepository struct {
	byEmail map[string]*domain.User
	byID    map[string]*domain.User
}

func newFakeUserRepository() *fakeUserRepository {
	return &fakeUserRepository{
		byEmail: make(map[string]*domain.User),
		byID:    make(map[string]*domain.User),
	}
}

func (f *fakeUserRepository) Create(_ context.Context, user *domain.User) error {
	if _, exists := f.byEmail[user.Email]; exists {
		return domain.ErrUserAlreadyExists
	}
	if user.ID == "" {
		user.ID = "user-" + user.Email
	}
	f.byEmail[user.Email] = user
	f.byID[user.ID] = user
	return nil
}

func (f *fakeUserRepository) FindByEmail(_ context.Context, email string) (*domain.User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUserRepository) FindByID(_ context.Context, id string) (*domain.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func TestUserRepository_Create(t *testing.T) {
	repo := newFakeUserRepository()

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hashed_password",
	}

	err := repo.Create(context.Background(), user)
	assert.NoError(t, err)
	assert.NotEmpty(t, user.ID)
}

func TestUserRepository_Create_DuplicateEmail(t *testing.T) {
	repo := newFakeUserRepository()

	user1 := &domain.User{Email: "test@example.com", PasswordHash: "hash1"}
	user2 := &domain.User{Email: "test@example.com", PasswordHash: "hash2"}

	err := repo.Create(context.Background(), user1)
	require.NoError(t, err)

	err = repo.Create(context.Background(), user2)
	assert.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrUserAlreadyExists)
}

func TestUserRepository_FindByEmail(t *testing.T) {
	repo := newFakeUserRepository()

	user := &domain.User{Email: "findme@example.com", PasswordHash: "hash"}
	err := repo.Create(context.Background(), user)
	require.NoError(t, err)

	found, err := repo.FindByEmail(context.Background(), "findme@example.com")
	assert.NoError(t, err)
	assert.Equal(t, user.ID, found.ID)
	assert.Equal(t, user.Email, found.Email)
	assert.Equal(t, user.PasswordHash, found.PasswordHash)
}

func TestUserRepository_FindByEmail_NotFound(t *testing.T) {
	repo := newFakeUserRepository()

	_, err := repo.FindByEmail(context.Background(), "nonexistent@example.com")
	assert.ErrorIs(t, err, domain.ErrUserNotFound)
}

func TestUserRepository_FindByID(t *testing.T) {
	repo := newFakeUserRepository()

	user := &domain.User{Email: "findbyid@example.com", PasswordHash: "hash"}
	err := repo.Create(context.Background(), user)
	require.NoError(t, err)

	found, err := repo.FindByID(context.Background(), user.ID)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, found.ID)
}

func TestUserRepository_FindByID_NotFound(t *testing.T) {
	repo := newFakeUserRepository()

	_, err := repo.FindByID(context.Background(), "non-existent-id")
	assert.ErrorIs(t, err, domain.ErrUserNotFound)
}