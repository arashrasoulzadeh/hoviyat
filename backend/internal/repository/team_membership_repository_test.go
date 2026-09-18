package repository

import (
	"context"
	"testing"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTeamMembershipRepository struct {
	byKey map[string]*domain.TeamMembership
}

func newFakeTeamMembershipRepository() *fakeTeamMembershipRepository {
	return &fakeTeamMembershipRepository{byKey: make(map[string]*domain.TeamMembership)}
}

func teamMembershipKey(userID, teamID string) string {
	return userID + "|" + teamID
}

func (f *fakeTeamMembershipRepository) Create(_ context.Context, tm *domain.TeamMembership) error {
	key := teamMembershipKey(tm.UserID, tm.TeamID)
	if _, exists := f.byKey[key]; exists {
		return domain.ErrTeamMembershipAlreadyExists
	}
	f.byKey[key] = tm
	return nil
}

func (f *fakeTeamMembershipRepository) FindByUserAndTeam(_ context.Context, userID, teamID string) (*domain.TeamMembership, error) {
	m, ok := f.byKey[teamMembershipKey(userID, teamID)]
	if !ok {
		return nil, domain.ErrTeamMembershipNotFound
	}
	return m, nil
}

func (f *fakeTeamMembershipRepository) ListByUser(_ context.Context, userID string) ([]*domain.TeamMembership, error) {
	var out []*domain.TeamMembership
	for _, m := range f.byKey {
		if m.UserID == userID {
			out = append(out, m)
		}
	}
	return out, nil
}

func (f *fakeTeamMembershipRepository) ListByTeam(_ context.Context, teamID string) ([]*domain.TeamMembership, error) {
	var out []*domain.TeamMembership
	for _, m := range f.byKey {
		if m.TeamID == teamID {
			out = append(out, m)
		}
	}
	return out, nil
}

func (f *fakeTeamMembershipRepository) UpdateRoles(_ context.Context, userID, teamID string, roles []string) error {
	m, ok := f.byKey[teamMembershipKey(userID, teamID)]
	if !ok {
		return domain.ErrTeamMembershipNotFound
	}
	m.Roles = roles
	return nil
}

func (f *fakeTeamMembershipRepository) Delete(_ context.Context, userID, teamID string) error {
	delete(f.byKey, teamMembershipKey(userID, teamID))
	return nil
}

func TestTeamMembershipRepository_Create(t *testing.T) {
	repo := newFakeTeamMembershipRepository()

	tm := &domain.TeamMembership{
		UserID: "user-1",
		TeamID: "team-1",
		Roles:  []string{"member"},
	}

	err := repo.Create(context.Background(), tm)
	assert.NoError(t, err)
}

func TestTeamMembershipRepository_Create_Duplicate(t *testing.T) {
	repo := newFakeTeamMembershipRepository()

	tm1 := &domain.TeamMembership{UserID: "user-1", TeamID: "team-1", Roles: []string{"member"}}
	tm2 := &domain.TeamMembership{UserID: "user-1", TeamID: "team-1", Roles: []string{"admin"}}

	err := repo.Create(context.Background(), tm1)
	require.NoError(t, err)

	err = repo.Create(context.Background(), tm2)
	assert.ErrorIs(t, err, domain.ErrTeamMembershipAlreadyExists)
}

func TestTeamMembershipRepository_FindByUserAndTeam(t *testing.T) {
	repo := newFakeTeamMembershipRepository()

	tm := &domain.TeamMembership{UserID: "user-1", TeamID: "team-1", Roles: []string{"member"}}
	err := repo.Create(context.Background(), tm)
	require.NoError(t, err)

	found, err := repo.FindByUserAndTeam(context.Background(), "user-1", "team-1")
	assert.NoError(t, err)
	assert.Equal(t, tm.UserID, found.UserID)
	assert.Equal(t, tm.TeamID, found.TeamID)
	assert.Equal(t, tm.Roles, found.Roles)
}

func TestTeamMembershipRepository_FindByUserAndTeam_NotFound(t *testing.T) {
	repo := newFakeTeamMembershipRepository()

	_, err := repo.FindByUserAndTeam(context.Background(), "user-1", "team-1")
	assert.ErrorIs(t, err, domain.ErrTeamMembershipNotFound)
}

func TestTeamMembershipRepository_ListByUser(t *testing.T) {
	repo := newFakeTeamMembershipRepository()

	tm1 := &domain.TeamMembership{UserID: "user-1", TeamID: "team-1", Roles: []string{"member"}}
	tm2 := &domain.TeamMembership{UserID: "user-1", TeamID: "team-2", Roles: []string{"admin"}}
	tm3 := &domain.TeamMembership{UserID: "user-2", TeamID: "team-1", Roles: []string{"member"}}

	repo.Create(context.Background(), tm1)
	repo.Create(context.Background(), tm2)
	repo.Create(context.Background(), tm3)

	memberships, err := repo.ListByUser(context.Background(), "user-1")
	assert.NoError(t, err)
	assert.Len(t, memberships, 2)

	teamIDs := make(map[string]bool)
	for _, m := range memberships {
		teamIDs[m.TeamID] = true
	}
	assert.True(t, teamIDs["team-1"])
	assert.True(t, teamIDs["team-2"])
}

func TestTeamMembershipRepository_ListByTeam(t *testing.T) {
	repo := newFakeTeamMembershipRepository()

	tm1 := &domain.TeamMembership{UserID: "user-1", TeamID: "team-1", Roles: []string{"member"}}
	tm2 := &domain.TeamMembership{UserID: "user-2", TeamID: "team-1", Roles: []string{"admin"}}
	tm3 := &domain.TeamMembership{UserID: "user-3", TeamID: "team-2", Roles: []string{"member"}}

	repo.Create(context.Background(), tm1)
	repo.Create(context.Background(), tm2)
	repo.Create(context.Background(), tm3)

	memberships, err := repo.ListByTeam(context.Background(), "team-1")
	assert.NoError(t, err)
	assert.Len(t, memberships, 2)

	userIDs := make(map[string]bool)
	for _, m := range memberships {
		userIDs[m.UserID] = true
	}
	assert.True(t, userIDs["user-1"])
	assert.True(t, userIDs["user-2"])
}

func TestTeamMembershipRepository_UpdateRoles(t *testing.T) {
	repo := newFakeTeamMembershipRepository()

	tm := &domain.TeamMembership{UserID: "user-1", TeamID: "team-1", Roles: []string{"member"}}
	err := repo.Create(context.Background(), tm)
	require.NoError(t, err)

	err = repo.UpdateRoles(context.Background(), "user-1", "team-1", []string{"admin", "editor"})
	assert.NoError(t, err)

	found, err := repo.FindByUserAndTeam(context.Background(), "user-1", "team-1")
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"admin", "editor"}, found.Roles)
}

func TestTeamMembershipRepository_UpdateRoles_NotFound(t *testing.T) {
	repo := newFakeTeamMembershipRepository()

	err := repo.UpdateRoles(context.Background(), "user-1", "team-1", []string{"admin"})
	assert.ErrorIs(t, err, domain.ErrTeamMembershipNotFound)
}

func TestTeamMembershipRepository_Delete(t *testing.T) {
	repo := newFakeTeamMembershipRepository()

	tm := &domain.TeamMembership{UserID: "user-1", TeamID: "team-1", Roles: []string{"member"}}
	err := repo.Create(context.Background(), tm)
	require.NoError(t, err)

	err = repo.Delete(context.Background(), "user-1", "team-1")
	assert.NoError(t, err)

	_, err = repo.FindByUserAndTeam(context.Background(), "user-1", "team-1")
	assert.ErrorIs(t, err, domain.ErrTeamMembershipNotFound)
}

func TestTeamMembershipRepository_Delete_NotFound(t *testing.T) {
	repo := newFakeTeamMembershipRepository()

	err := repo.Delete(context.Background(), "user-1", "team-1")
	assert.NoError(t, err)
}