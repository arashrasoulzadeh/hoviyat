package repository

import (
	"context"
	"testing"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTenantRepository struct {
	byID   map[string]*domain.Tenant
	bySlug map[string]*domain.Tenant
}

func newFakeTenantRepository() *fakeTenantRepository {
	return &fakeTenantRepository{
		byID:   make(map[string]*domain.Tenant),
		bySlug: make(map[string]*domain.Tenant),
	}
}

func (f *fakeTenantRepository) Create(_ context.Context, tenant *domain.Tenant) error {
	if tenant.ID == "" {
		tenant.ID = "tenant-" + tenant.Slug
	}
	if _, exists := f.byID[tenant.ID]; exists {
		return domain.ErrTenantAlreadyExists
	}
	if _, exists := f.bySlug[tenant.Slug]; exists {
		return domain.ErrTenantAlreadyExists
	}
	f.byID[tenant.ID] = tenant
	f.bySlug[tenant.Slug] = tenant
	return nil
}

func (f *fakeTenantRepository) FindByID(_ context.Context, id string) (*domain.Tenant, error) {
	t, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrTenantNotFound
	}
	return t, nil
}

func (f *fakeTenantRepository) FindBySlug(_ context.Context, slug string) (*domain.Tenant, error) {
	t, ok := f.bySlug[slug]
	if !ok {
		return nil, domain.ErrTenantNotFound
	}
	return t, nil
}

func (f *fakeTenantRepository) UpdateStatus(_ context.Context, id string, status domain.TenantStatus) error {
	t, ok := f.byID[id]
	if !ok {
		return domain.ErrTenantNotFound
	}
	t.Status = status
	return nil
}

func (f *fakeTenantRepository) Delete(_ context.Context, id string) error {
	t, ok := f.byID[id]
	if !ok {
		return domain.ErrTenantNotFound
	}
	delete(f.byID, id)
	delete(f.bySlug, t.Slug)
	return nil
}

func TestTenantRepository_Create(t *testing.T) {
	repo := newFakeTenantRepository()

	tenant := &domain.Tenant{
		Name:   "Test Tenant",
		Slug:   "test-tenant",
		Status: domain.TenantStatusActive,
	}

	err := repo.Create(context.Background(), tenant)
	assert.NoError(t, err)
	assert.NotEmpty(t, tenant.ID)
	assert.Equal(t, domain.TenantStatusActive, tenant.Status)
}

func TestTenantRepository_Create_DuplicateSlug(t *testing.T) {
	repo := newFakeTenantRepository()

	tenant1 := &domain.Tenant{Name: "Test 1", Slug: "test", Status: domain.TenantStatusActive}
	tenant2 := &domain.Tenant{Name: "Test 2", Slug: "test", Status: domain.TenantStatusActive}

	err := repo.Create(context.Background(), tenant1)
	require.NoError(t, err)

	err = repo.Create(context.Background(), tenant2)
	assert.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrTenantAlreadyExists)
}

func TestTenantRepository_FindByID(t *testing.T) {
	repo := newFakeTenantRepository()

	tenant := &domain.Tenant{Name: "Find Me", Slug: "find-me", Status: domain.TenantStatusActive}
	err := repo.Create(context.Background(), tenant)
	require.NoError(t, err)

	found, err := repo.FindByID(context.Background(), tenant.ID)
	assert.NoError(t, err)
	assert.Equal(t, tenant.ID, found.ID)
	assert.Equal(t, tenant.Slug, found.Slug)
}

func TestTenantRepository_FindBySlug(t *testing.T) {
	repo := newFakeTenantRepository()

	tenant := &domain.Tenant{Name: "Find By Slug", Slug: "find-by-slug", Status: domain.TenantStatusActive}
	err := repo.Create(context.Background(), tenant)
	require.NoError(t, err)

	found, err := repo.FindBySlug(context.Background(), "find-by-slug")
	assert.NoError(t, err)
	assert.Equal(t, tenant.ID, found.ID)
	assert.Equal(t, tenant.Slug, found.Slug)
}

func TestTenantRepository_FindByID_NotFound(t *testing.T) {
	repo := newFakeTenantRepository()

	_, err := repo.FindByID(context.Background(), "non-existent")
	assert.ErrorIs(t, err, domain.ErrTenantNotFound)
}

func TestTenantRepository_FindBySlug_NotFound(t *testing.T) {
	repo := newFakeTenantRepository()

	_, err := repo.FindBySlug(context.Background(), "non-existent")
	assert.ErrorIs(t, err, domain.ErrTenantNotFound)
}

func TestTenantRepository_UpdateStatus(t *testing.T) {
	repo := newFakeTenantRepository()

	tenant := &domain.Tenant{Name: "Status Test", Slug: "status-test", Status: domain.TenantStatusActive}
	err := repo.Create(context.Background(), tenant)
	require.NoError(t, err)

	err = repo.UpdateStatus(context.Background(), tenant.ID, domain.TenantStatusSuspended)
	assert.NoError(t, err)

	found, err := repo.FindByID(context.Background(), tenant.ID)
	assert.NoError(t, err)
	assert.Equal(t, domain.TenantStatusSuspended, found.Status)
}

func TestTenantRepository_UpdateStatus_NotFound(t *testing.T) {
	repo := newFakeTenantRepository()

	err := repo.UpdateStatus(context.Background(), "non-existent", domain.TenantStatusSuspended)
	assert.ErrorIs(t, err, domain.ErrTenantNotFound)
}

func TestTenantRepository_Delete(t *testing.T) {
	repo := newFakeTenantRepository()

	tenant := &domain.Tenant{Name: "Delete Me", Slug: "delete-me", Status: domain.TenantStatusActive}
	err := repo.Create(context.Background(), tenant)
	require.NoError(t, err)

	err = repo.Delete(context.Background(), tenant.ID)
	assert.NoError(t, err)

	_, err = repo.FindByID(context.Background(), tenant.ID)
	assert.ErrorIs(t, err, domain.ErrTenantNotFound)
}

func TestTenantRepository_Delete_NotFound(t *testing.T) {
	repo := newFakeTenantRepository()

	err := repo.Delete(context.Background(), "non-existent")
	assert.ErrorIs(t, err, domain.ErrTenantNotFound)
}