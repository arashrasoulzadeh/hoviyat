package repository

import (
	"context"
	"testing"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTeamRepository struct {
	byID     map[string]*domain.Team
	bySlug   map[string]*domain.Team // key: tenantID|slug
}

func newFakeTeamRepository() *fakeTeamRepository {
	return &fakeTeamRepository{
		byID:   make(map[string]*domain.Team),
		bySlug: make(map[string]*domain.Team),
	}
}

func (f *fakeTeamRepository) Create(_ context.Context, team *domain.Team) error {
	if team.ID == "" {
		team.ID = "team-" + team.TenantID + "-" + team.Slug
	}
	if _, exists := f.byID[team.ID]; exists {
		return domain.ErrTeamAlreadyExists
	}
	slugKey := team.TenantID + "|" + team.Slug
	if _, exists := f.bySlug[slugKey]; exists {
		return domain.ErrTeamAlreadyExists
	}
	f.byID[team.ID] = team
	f.bySlug[slugKey] = team
	return nil
}

func (f *fakeTeamRepository) FindByID(_ context.Context, id string) (*domain.Team, error) {
	t, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrTeamNotFound
	}
	return t, nil
}

func (f *fakeTeamRepository) FindBySlug(_ context.Context, tenantID, slug string) (*domain.Team, error) {
	t, ok := f.bySlug[tenantID+"|"+slug]
	if !ok {
		return nil, domain.ErrTeamNotFound
	}
	return t, nil
}

func (f *fakeTeamRepository) ListByTenant(_ context.Context, tenantID string) ([]*domain.Team, error) {
	var out []*domain.Team
	for _, t := range f.byID {
		if t.TenantID == tenantID {
			out = append(out, t)
		}
	}
	return out, nil
}

func (f *fakeTeamRepository) Update(_ context.Context, team *domain.Team) error {
	if _, ok := f.byID[team.ID]; !ok {
		return domain.ErrTeamNotFound
	}
	f.byID[team.ID] = team
	slugKey := team.TenantID + "|" + team.Slug
	f.bySlug[slugKey] = team
	return nil
}

func (f *fakeTeamRepository) Delete(_ context.Context, id string) error {
	t, ok := f.byID[id]
	if !ok {
		return domain.ErrTeamNotFound
	}
	delete(f.byID, id)
	delete(f.bySlug, t.TenantID+"|"+t.Slug)
	return nil
}

func TestTeamRepository_Create(t *testing.T) {
	repo := newFakeTeamRepository()

	team := &domain.Team{
		TenantID: "tenant-1",
		Name:     "Test Team",
		Slug:     "test-team",
	}

	err := repo.Create(context.Background(), team)
	assert.NoError(t, err)
	assert.NotEmpty(t, team.ID)
}

func TestTeamRepository_Create_DuplicateSlug(t *testing.T) {
	repo := newFakeTeamRepository()

	team1 := &domain.Team{TenantID: "tenant-1", Name: "Team 1", Slug: "team-a"}
	team2 := &domain.Team{TenantID: "tenant-1", Name: "Team 2", Slug: "team-a"}

	err := repo.Create(context.Background(), team1)
	require.NoError(t, err)

	err = repo.Create(context.Background(), team2)
	assert.ErrorIs(t, err, domain.ErrTeamAlreadyExists)
}

func TestTeamRepository_Create_DifferentTenantsSameSlug(t *testing.T) {
	repo := newFakeTeamRepository()

	team1 := &domain.Team{TenantID: "tenant-1", Name: "Team A", Slug: "team"}
	team2 := &domain.Team{TenantID: "tenant-2", Name: "Team A", Slug: "team"}

	err := repo.Create(context.Background(), team1)
	require.NoError(t, err)

	err = repo.Create(context.Background(), team2)
	assert.NoError(t, err) // Different tenants can have same slug
}

func TestTeamRepository_FindByID(t *testing.T) {
	repo := newFakeTeamRepository()

	team := &domain.Team{TenantID: "tenant-1", Name: "Find Me", Slug: "find-me"}
	err := repo.Create(context.Background(), team)
	require.NoError(t, err)

	found, err := repo.FindByID(context.Background(), team.ID)
	assert.NoError(t, err)
	assert.Equal(t, team.ID, found.ID)
}

func TestTeamRepository_FindBySlug(t *testing.T) {
	repo := newFakeTeamRepository()

	team := &domain.Team{TenantID: "tenant-1", Name: "Find By Slug", Slug: "find-by-slug"}
	err := repo.Create(context.Background(), team)
	require.NoError(t, err)

	found, err := repo.FindBySlug(context.Background(), "tenant-1", "find-by-slug")
	assert.NoError(t, err)
	assert.Equal(t, team.ID, found.ID)
}

func TestTeamRepository_FindByID_NotFound(t *testing.T) {
	repo := newFakeTeamRepository()

	_, err := repo.FindByID(context.Background(), "non-existent")
	assert.ErrorIs(t, err, domain.ErrTeamNotFound)
}

func TestTeamRepository_FindBySlug_NotFound(t *testing.T) {
	repo := newFakeTeamRepository()

	_, err := repo.FindBySlug(context.Background(), "tenant-1", "non-existent")
	assert.ErrorIs(t, err, domain.ErrTeamNotFound)
}

func TestTeamRepository_ListByTenant(t *testing.T) {
	repo := newFakeTeamRepository()

	t1 := &domain.Team{TenantID: "tenant-1", Name: "Team 1", Slug: "team-1"}
	t2 := &domain.Team{TenantID: "tenant-1", Name: "Team 2", Slug: "team-2"}
	t3 := &domain.Team{TenantID: "tenant-2", Name: "Team 3", Slug: "team-3"}

	repo.Create(context.Background(), t1)
	repo.Create(context.Background(), t2)
	repo.Create(context.Background(), t3)

	teams, err := repo.ListByTenant(context.Background(), "tenant-1")
	assert.NoError(t, err)
	assert.Len(t, teams, 2)
}

func TestTeamRepository_Update(t *testing.T) {
	repo := newFakeTeamRepository()

	team := &domain.Team{TenantID: "tenant-1", Name: "Original", Slug: "original"}
	err := repo.Create(context.Background(), team)
	require.NoError(t, err)

	team.Name = "Updated"
	team.Slug = "updated"
	err = repo.Update(context.Background(), team)
	assert.NoError(t, err)

	found, err := repo.FindByID(context.Background(), team.ID)
	assert.NoError(t, err)
	assert.Equal(t, "Updated", found.Name)
	assert.Equal(t, "updated", found.Slug)
}

func TestTeamRepository_Update_NotFound(t *testing.T) {
	repo := newFakeTeamRepository()

	team := &domain.Team{ID: "non-existent", TenantID: "tenant-1", Name: "Test", Slug: "test"}
	err := repo.Update(context.Background(), team)
	assert.ErrorIs(t, err, domain.ErrTeamNotFound)
}

func TestTeamRepository_Delete(t *testing.T) {
	repo := newFakeTeamRepository()

	team := &domain.Team{TenantID: "tenant-1", Name: "Delete Me", Slug: "delete-me"}
	err := repo.Create(context.Background(), team)
	require.NoError(t, err)

	err = repo.Delete(context.Background(), team.ID)
	assert.NoError(t, err)

	_, err = repo.FindByID(context.Background(), team.ID)
	assert.ErrorIs(t, err, domain.ErrTeamNotFound)
}