package domain

import (
	"context"
	"errors"
	"time"
)

type Team struct {
	ID        string
	TenantID  string
	Name      string
	Slug      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

var (
	ErrTeamNotFound      = errors.New("team not found")
	ErrTeamAlreadyExists = errors.New("team already exists")
)

type TeamRepository interface {
	Create(ctx context.Context, team *Team) error
	FindByID(ctx context.Context, id string) (*Team, error)
	FindBySlug(ctx context.Context, tenantID, slug string) (*Team, error)
	ListByTenant(ctx context.Context, tenantID string) ([]*Team, error)
	Update(ctx context.Context, team *Team) error
	Delete(ctx context.Context, id string) error
}

type TeamMembership struct {
	UserID    string
	TeamID    string
	Roles     []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

var (
	ErrTeamMembershipNotFound      = errors.New("team membership not found")
	ErrTeamMembershipAlreadyExists = errors.New("team membership already exists")
)

type TeamMembershipRepository interface {
	Create(ctx context.Context, tm *TeamMembership) error
	FindByUserAndTeam(ctx context.Context, userID, teamID string) (*TeamMembership, error)
	ListByUser(ctx context.Context, userID string) ([]*TeamMembership, error)
	ListByTeam(ctx context.Context, teamID string) ([]*TeamMembership, error)
	UpdateRoles(ctx context.Context, userID, teamID string, roles []string) error
	Delete(ctx context.Context, userID, teamID string) error
}