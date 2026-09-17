package domain

import (
	"context"
	"errors"
	"time"
)

// Membership links a user to a tenant with tenant-scoped roles — analogous
// to Slack/GitHub org membership (PRD §6). A single user account can hold
// many memberships, one per tenant, each with independent roles so that
// permissions in one tenant never leak into another.
type Membership struct {
	UserID    string
	TenantID  string
	Roles     []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

var (
	ErrMembershipNotFound      = errors.New("membership not found")
	ErrMembershipAlreadyExists = errors.New("membership already exists")
)

type MembershipRepository interface {
	Create(ctx context.Context, membership *Membership) error
	FindByUserAndTenant(ctx context.Context, userID, tenantID string) (*Membership, error)
	ListByUser(ctx context.Context, userID string) ([]*Membership, error)
	UpdateRoles(ctx context.Context, userID, tenantID string, roles []string) error
	Delete(ctx context.Context, userID, tenantID string) error
}
