package repository

import (
	"context"
	"testing"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeMembershipRepository struct {
	byKey map[string]*domain.Membership
}

func newFakeMembershipRepository() *fakeMembershipRepository {
	return &fakeMembershipRepository{byKey: make(map[string]*domain.Membership)}
}

func membershipKey(userID, tenantID string) string {
	return userID + "|" + tenantID
}

func (f *fakeMembershipRepository) Create(_ context.Context, membership *domain.Membership) error {
	key := membershipKey(membership.UserID, membership.TenantID)
	if _, exists := f.byKey[key]; exists {
		return domain.ErrMembershipAlreadyExists
	}
	f.byKey[key] = membership
	return nil
}

func (f *fakeMembershipRepository) FindByUserAndTenant(_ context.Context, userID, tenantID string) (*domain.Membership, error) {
	m, ok := f.byKey[membershipKey(userID, tenantID)]
	if !ok {
		return nil, domain.ErrMembershipNotFound
	}
	return m, nil
}

func (f *fakeMembershipRepository) ListByUser(_ context.Context, userID string) ([]*domain.Membership, error) {
	var out []*domain.Membership
	for _, m := range f.byKey {
		if m.UserID == userID {
			out = append(out, m)
		}
	}
	return out, nil
}

func (f *fakeMembershipRepository) UpdateRoles(_ context.Context, userID, tenantID string, roles []string) error {
	m, ok := f.byKey[membershipKey(userID, tenantID)]
	if !ok {
		return domain.ErrMembershipNotFound
	}
	m.Roles = roles
	return nil
}

func (f *fakeMembershipRepository) Delete(_ context.Context, userID, tenantID string) error {
	delete(f.byKey, membershipKey(userID, tenantID))
	return nil
}

func TestMembershipRepository_Create(t *testing.T) {
	repo := newFakeMembershipRepository()

	membership := &domain.Membership{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Roles:    []string{"admin"},
	}

	err := repo.Create(context.Background(), membership)
	assert.NoError(t, err)
}

func TestMembershipRepository_Create_Duplicate(t *testing.T) {
	repo := newFakeMembershipRepository()

	m1 := &domain.Membership{UserID: "user-1", TenantID: "tenant-1", Roles: []string{"admin"}}
	m2 := &domain.Membership{UserID: "user-1", TenantID: "tenant-1", Roles: []string{"member"}}

	err := repo.Create(context.Background(), m1)
	require.NoError(t, err)

	err = repo.Create(context.Background(), m2)
	assert.ErrorIs(t, err, domain.ErrMembershipAlreadyExists)
}

func TestMembershipRepository_FindByUserAndTenant(t *testing.T) {
	repo := newFakeMembershipRepository()

	membership := &domain.Membership{UserID: "user-1", TenantID: "tenant-1", Roles: []string{"admin"}}
	err := repo.Create(context.Background(), membership)
	require.NoError(t, err)

	found, err := repo.FindByUserAndTenant(context.Background(), "user-1", "tenant-1")
	assert.NoError(t, err)
	assert.Equal(t, membership.UserID, found.UserID)
	assert.Equal(t, membership.TenantID, found.TenantID)
	assert.Equal(t, membership.Roles, found.Roles)
}

func TestMembershipRepository_FindByUserAndTenant_NotFound(t *testing.T) {
	repo := newFakeMembershipRepository()

	_, err := repo.FindByUserAndTenant(context.Background(), "user-1", "tenant-1")
	assert.ErrorIs(t, err, domain.ErrMembershipNotFound)
}

func TestMembershipRepository_ListByUser(t *testing.T) {
	repo := newFakeMembershipRepository()

	m1 := &domain.Membership{UserID: "user-1", TenantID: "tenant-1", Roles: []string{"admin"}}
	m2 := &domain.Membership{UserID: "user-1", TenantID: "tenant-2", Roles: []string{"member"}}
	m3 := &domain.Membership{UserID: "user-2", TenantID: "tenant-1", Roles: []string{"admin"}}

	repo.Create(context.Background(), m1)
	repo.Create(context.Background(), m2)
	repo.Create(context.Background(), m3)

	memberships, err := repo.ListByUser(context.Background(), "user-1")
	assert.NoError(t, err)
	assert.Len(t, memberships, 2)

	tenantIDs := make(map[string]bool)
	for _, m := range memberships {
		tenantIDs[m.TenantID] = true
	}
	assert.True(t, tenantIDs["tenant-1"])
	assert.True(t, tenantIDs["tenant-2"])
}

func TestMembershipRepository_UpdateRoles(t *testing.T) {
	repo := newFakeMembershipRepository()

	membership := &domain.Membership{UserID: "user-1", TenantID: "tenant-1", Roles: []string{"member"}}
	err := repo.Create(context.Background(), membership)
	require.NoError(t, err)

	err = repo.UpdateRoles(context.Background(), "user-1", "tenant-1", []string{"admin", "editor"})
	assert.NoError(t, err)

	found, err := repo.FindByUserAndTenant(context.Background(), "user-1", "tenant-1")
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"admin", "editor"}, found.Roles)
}

func TestMembershipRepository_UpdateRoles_NotFound(t *testing.T) {
	repo := newFakeMembershipRepository()

	err := repo.UpdateRoles(context.Background(), "user-1", "tenant-1", []string{"admin"})
	assert.ErrorIs(t, err, domain.ErrMembershipNotFound)
}

func TestMembershipRepository_Delete(t *testing.T) {
	repo := newFakeMembershipRepository()

	membership := &domain.Membership{UserID: "user-1", TenantID: "tenant-1", Roles: []string{"admin"}}
	err := repo.Create(context.Background(), membership)
	require.NoError(t, err)

	err = repo.Delete(context.Background(), "user-1", "tenant-1")
	assert.NoError(t, err)

	_, err = repo.FindByUserAndTenant(context.Background(), "user-1", "tenant-1")
	assert.ErrorIs(t, err, domain.ErrMembershipNotFound)
}

func TestMembershipRepository_Delete_NotFound(t *testing.T) {
	repo := newFakeMembershipRepository()

	err := repo.Delete(context.Background(), "user-1", "tenant-1")
	// Delete is idempotent in our fake
	assert.NoError(t, err)
}