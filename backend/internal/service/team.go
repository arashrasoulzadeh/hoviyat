package service

import (
	"context"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

type TeamService struct {
	teams domain.TeamRepository
}

func NewTeamService(teams domain.TeamRepository) *TeamService {
	return &TeamService{teams: teams}
}

func (s *TeamService) Create(ctx context.Context, tenantID, name, slug string) (*domain.Team, error) {
	team := &domain.Team{
		TenantID: tenantID,
		Name:     name,
		Slug:     slug,
	}
	if err := s.teams.Create(ctx, team); err != nil {
		return nil, err
	}
	return team, nil
}

func (s *TeamService) GetByID(ctx context.Context, id string) (*domain.Team, error) {
	return s.teams.FindByID(ctx, id)
}

func (s *TeamService) GetBySlug(ctx context.Context, tenantID, slug string) (*domain.Team, error) {
	return s.teams.FindBySlug(ctx, tenantID, slug)
}

func (s *TeamService) ListByTenant(ctx context.Context, tenantID string) ([]*domain.Team, error) {
	return s.teams.ListByTenant(ctx, tenantID)
}

func (s *TeamService) Update(ctx context.Context, team *domain.Team) error {
	return s.teams.Update(ctx, team)
}

func (s *TeamService) Delete(ctx context.Context, id string) error {
	return s.teams.Delete(ctx, id)
}

type TeamMembershipService struct {
	teamMemberships domain.TeamMembershipRepository
	teams           domain.TeamRepository
}

func NewTeamMembershipService(teamMemberships domain.TeamMembershipRepository, teams domain.TeamRepository) *TeamMembershipService {
	return &TeamMembershipService{teamMemberships: teamMemberships, teams: teams}
}

func (s *TeamMembershipService) AddMember(ctx context.Context, userID, teamID string, roles []string) (*domain.TeamMembership, error) {
	_, err := s.teams.FindByID(ctx, teamID)
	if err != nil {
		return nil, err
	}
	tm := &domain.TeamMembership{
		UserID: userID,
		TeamID: teamID,
		Roles:  roles,
	}
	if err := s.teamMemberships.Create(ctx, tm); err != nil {
		return nil, err
	}
	return tm, nil
}

func (s *TeamMembershipService) GetMembership(ctx context.Context, userID, teamID string) (*domain.TeamMembership, error) {
	return s.teamMemberships.FindByUserAndTeam(ctx, userID, teamID)
}

func (s *TeamMembershipService) ListUserMemberships(ctx context.Context, userID string) ([]*domain.TeamMembership, error) {
	return s.teamMemberships.ListByUser(ctx, userID)
}

func (s *TeamMembershipService) ListTeamMembers(ctx context.Context, teamID string) ([]*domain.TeamMembership, error) {
	return s.teamMemberships.ListByTeam(ctx, teamID)
}

func (s *TeamMembershipService) UpdateRoles(ctx context.Context, userID, teamID string, roles []string) error {
	return s.teamMemberships.UpdateRoles(ctx, userID, teamID, roles)
}

func (s *TeamMembershipService) RemoveMember(ctx context.Context, userID, teamID string) error {
	return s.teamMemberships.Delete(ctx, userID, teamID)
}