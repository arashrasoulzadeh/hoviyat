package repository

import (
	"context"
	"testing"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeACLRepository struct {
	byID          map[string]*domain.ACLPermission
	bySubject     map[string]*domain.ACLPermission // key: tenantID|subjectType|subjectID
	byResource    map[string]*domain.ACLPermission // key: tenantID|resourceType|resourceID
}

func newFakeACLRepository() *fakeACLRepository {
	return &fakeACLRepository{
		byID:       make(map[string]*domain.ACLPermission),
		bySubject:  make(map[string]*domain.ACLPermission),
		byResource: make(map[string]*domain.ACLPermission),
	}
}

func (f *fakeACLRepository) Create(_ context.Context, acl *domain.ACLPermission) error {
	if acl.ID == "" {
		acl.ID = "acl-" + acl.TenantID + "-" + acl.SubjectType + "-" + acl.SubjectID + "-" + acl.ResourceType + "-" + acl.ResourceID + "-" + acl.Permission
	}
	if _, exists := f.byID[acl.ID]; exists {
		return domain.ErrACLAlreadyExists
	}
	subKey := acl.TenantID + "|" + acl.SubjectType + "|" + acl.SubjectID
	resKey := acl.TenantID + "|" + acl.ResourceType + "|" + acl.ResourceID
	f.byID[acl.ID] = acl
	f.bySubject[subKey] = acl
	f.byResource[resKey] = acl
	return nil
}

func (f *fakeACLRepository) FindByID(_ context.Context, id string) (*domain.ACLPermission, error) {
	a, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrACLNotFound
	}
	return a, nil
}

func (f *fakeACLRepository) FindBySubject(_ context.Context, tenantID, subjectType, subjectID string) ([]*domain.ACLPermission, error) {
	key := tenantID + "|" + subjectType + "|" + subjectID
	a, ok := f.bySubject[key]
	if !ok {
		return []*domain.ACLPermission{}, nil
	}
	return []*domain.ACLPermission{a}, nil
}

func (f *fakeACLRepository) FindByResource(_ context.Context, tenantID, resourceType, resourceID string) ([]*domain.ACLPermission, error) {
	key := tenantID + "|" + resourceType + "|" + resourceID
	a, ok := f.byResource[key]
	if !ok {
		return []*domain.ACLPermission{}, nil
	}
	return []*domain.ACLPermission{a}, nil
}

func (f *fakeACLRepository) CheckPermission(_ context.Context, tenantID, subjectType, subjectID, resourceType, resourceID, permission string) (*domain.ACLPermission, error) {
	// Simplified - just check by resource
	key := tenantID + "|" + resourceType + "|" + resourceID
	a, ok := f.byResource[key]
	if !ok || a.Permission != permission {
		return nil, domain.ErrACLNotFound
	}
	return a, nil
}

func (f *fakeACLRepository) Delete(_ context.Context, id string) error {
	a, ok := f.byID[id]
	if !ok {
		return domain.ErrACLNotFound
	}
	delete(f.byID, id)
	delete(f.bySubject, a.TenantID+"|"+a.SubjectType+"|"+a.SubjectID)
	delete(f.byResource, a.TenantID+"|"+a.ResourceType+"|"+a.ResourceID)
	return nil
}

func (f *fakeACLRepository) DeleteBySubjectAndResource(_ context.Context, tenantID, subjectType, subjectID, resourceType, resourceID string) error {
	// For test purposes, we'll just delete by resource key
	key := tenantID + "|" + resourceType + "|" + resourceID
	if a, ok := f.byResource[key]; ok {
		delete(f.byID, a.ID)
		delete(f.bySubject, a.TenantID+"|"+a.SubjectType+"|"+a.SubjectID)
		delete(f.byResource, key)
		return nil
	}
	return nil
}

func TestACLRepository_Create(t *testing.T) {
	repo := newFakeACLRepository()

	acl := &domain.ACLPermission{
		TenantID:      "tenant-1",
		SubjectType:   "user",
		SubjectID:     "user-1",
		ResourceType:  "document",
		ResourceID:    "doc-1",
		Permission:    "read",
		Effect:        "allow",
	}

	err := repo.Create(context.Background(), acl)
	assert.NoError(t, err)
	assert.NotEmpty(t, acl.ID)
}

func TestACLRepository_Create_Duplicate(t *testing.T) {
	repo := newFakeACLRepository()

	acl1 := &domain.ACLPermission{TenantID: "tenant-1", SubjectType: "user", SubjectID: "user-1", ResourceType: "doc", ResourceID: "doc-1", Permission: "read", Effect: "allow"}
	acl2 := &domain.ACLPermission{TenantID: "tenant-1", SubjectType: "user", SubjectID: "user-1", ResourceType: "doc", ResourceID: "doc-1", Permission: "read", Effect: "allow"}

	err := repo.Create(context.Background(), acl1)
	require.NoError(t, err)

	err = repo.Create(context.Background(), acl2)
	assert.ErrorIs(t, err, domain.ErrACLAlreadyExists)
}

func TestACLRepository_FindByID(t *testing.T) {
	repo := newFakeACLRepository()

	acl := &domain.ACLPermission{TenantID: "tenant-1", SubjectType: "user", SubjectID: "user-1", ResourceType: "doc", ResourceID: "doc-1", Permission: "read", Effect: "allow"}
	err := repo.Create(context.Background(), acl)
	require.NoError(t, err)

	found, err := repo.FindByID(context.Background(), acl.ID)
	assert.NoError(t, err)
	assert.Equal(t, acl.ID, found.ID)
}

func TestACLRepository_FindBySubject(t *testing.T) {
	repo := newFakeACLRepository()

	acl := &domain.ACLPermission{TenantID: "tenant-1", SubjectType: "user", SubjectID: "user-1", ResourceType: "doc", ResourceID: "doc-1", Permission: "read", Effect: "allow"}
	err := repo.Create(context.Background(), acl)
	require.NoError(t, err)

	acls, err := repo.FindBySubject(context.Background(), "tenant-1", "user", "user-1")
	assert.NoError(t, err)
	assert.Len(t, acls, 1)
	assert.Equal(t, acl.ID, acls[0].ID)
}

func TestACLRepository_FindByResource(t *testing.T) {
	repo := newFakeACLRepository()

	acl := &domain.ACLPermission{TenantID: "tenant-1", SubjectType: "user", SubjectID: "user-1", ResourceType: "doc", ResourceID: "doc-1", Permission: "read", Effect: "allow"}
	err := repo.Create(context.Background(), acl)
	require.NoError(t, err)

	acls, err := repo.FindByResource(context.Background(), "tenant-1", "doc", "doc-1")
	assert.NoError(t, err)
	assert.Len(t, acls, 1)
}

func TestACLRepository_CheckPermission_Allow(t *testing.T) {
	repo := newFakeACLRepository()

	acl := &domain.ACLPermission{TenantID: "tenant-1", SubjectType: "user", SubjectID: "user-1", ResourceType: "doc", ResourceID: "doc-1", Permission: "read", Effect: "allow"}
	err := repo.Create(context.Background(), acl)
	require.NoError(t, err)

	found, err := repo.CheckPermission(context.Background(), "tenant-1", "user", "user-1", "doc", "doc-1", "read")
	assert.NoError(t, err)
	assert.Equal(t, "allow", found.Effect)
}

func TestACLRepository_CheckPermission_Deny(t *testing.T) {
	repo := newFakeACLRepository()

	acl := &domain.ACLPermission{TenantID: "tenant-1", SubjectType: "user", SubjectID: "user-1", ResourceType: "doc", ResourceID: "doc-1", Permission: "read", Effect: "deny"}
	err := repo.Create(context.Background(), acl)
	require.NoError(t, err)

	found, err := repo.CheckPermission(context.Background(), "tenant-1", "user", "user-1", "doc", "doc-1", "read")
	assert.NoError(t, err)
	assert.Equal(t, "deny", found.Effect)
}

func TestACLRepository_CheckPermission_NotFound(t *testing.T) {
	repo := newFakeACLRepository()

	_, err := repo.CheckPermission(context.Background(), "tenant-1", "user", "user-1", "doc", "doc-1", "read")
	assert.ErrorIs(t, err, domain.ErrACLNotFound)
}

func TestACLRepository_Delete(t *testing.T) {
	repo := newFakeACLRepository()

	acl := &domain.ACLPermission{TenantID: "tenant-1", SubjectType: "user", SubjectID: "user-1", ResourceType: "doc", ResourceID: "doc-1", Permission: "read", Effect: "allow"}
	err := repo.Create(context.Background(), acl)
	require.NoError(t, err)

	err = repo.Delete(context.Background(), acl.ID)
	assert.NoError(t, err)

	_, err = repo.FindByID(context.Background(), acl.ID)
	assert.ErrorIs(t, err, domain.ErrACLNotFound)
}

func TestACLRepository_DeleteBySubjectAndResource(t *testing.T) {
	repo := newFakeACLRepository()

	acl := &domain.ACLPermission{TenantID: "tenant-1", SubjectType: "user", SubjectID: "user-1", ResourceType: "doc", ResourceID: "doc-1", Permission: "read", Effect: "allow"}
	err := repo.Create(context.Background(), acl)
	require.NoError(t, err)

	err = repo.DeleteBySubjectAndResource(context.Background(), "tenant-1", "user", "user-1", "doc", "doc-1")
	assert.NoError(t, err)

	_, err = repo.FindByID(context.Background(), acl.ID)
	assert.ErrorIs(t, err, domain.ErrACLNotFound)
}