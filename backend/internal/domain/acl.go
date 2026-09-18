package domain

import (
	"context"
	"errors"
	"time"
)

// ACLPermission represents an access control entry for a specific resource instance.
type ACLPermission struct {
	ID            string
	TenantID      string
	SubjectType   string // "user" or "team" or "role"
	SubjectID     string // user_id, team_id, or role name
	ResourceType  string // e.g., "document", "folder", "project"
	ResourceID    string // specific resource instance ID
	Permission    string // e.g., "read", "write", "delete", "admin"
	Effect        string // "allow" or "deny"
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

var (
	ErrACLNotFound      = errors.New("acl entry not found")
	ErrACLAlreadyExists = errors.New("acl entry already exists")
)

type ACLRepository interface {
	Create(ctx context.Context, acl *ACLPermission) error
	FindByID(ctx context.Context, id string) (*ACLPermission, error)
	FindBySubject(ctx context.Context, tenantID, subjectType, subjectID string) ([]*ACLPermission, error)
	FindByResource(ctx context.Context, tenantID, resourceType, resourceID string) ([]*ACLPermission, error)
	CheckPermission(ctx context.Context, tenantID, subjectType, subjectID, resourceType, resourceID, permission string) (*ACLPermission, error)
	Delete(ctx context.Context, id string) error
	DeleteBySubjectAndResource(ctx context.Context, tenantID, subjectType, subjectID, resourceType, resourceID string) error
}

// RolePermission represents a role-to-permission grant (replaces in-memory map).
type RolePermission struct {
	ID          string
	TenantID    string
	RoleName    string
	Permission  string
	CreatedAt   time.Time
}

type RolePermissionRepository interface {
	Create(ctx context.Context, rp *RolePermission) error
	FindByRole(ctx context.Context, tenantID, roleName string) ([]*RolePermission, error)
	FindByTenant(ctx context.Context, tenantID string) ([]*RolePermission, error)
	Delete(ctx context.Context, id string) error
	DeleteByRole(ctx context.Context, tenantID, roleName string) error
}

// Permission represents a permission definition (resource:action).
type Permission struct {
	ID          string
	TenantID    string
	Name        string // e.g., "document:read"
	Description string
	CreatedAt   time.Time
}

type PermissionRepository interface {
	Create(ctx context.Context, perm *Permission) error
	FindByID(ctx context.Context, id string) (*Permission, error)
	FindByTenant(ctx context.Context, tenantID string) ([]*Permission, error)
	Delete(ctx context.Context, id string) error
}

// Policy represents a versioned OPA/Rego policy.
type Policy struct {
	ID          string
	TenantID    string
	Name        string
	Description string
	Rego        string
	Version     int
	IsActive    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type PolicyRepository interface {
	Create(ctx context.Context, policy *Policy) error
	FindByID(ctx context.Context, id string) (*Policy, error)
	FindByName(ctx context.Context, tenantID, name string) (*Policy, error)
	FindActiveByTenant(ctx context.Context, tenantID string) ([]*Policy, error)
	ListByTenant(ctx context.Context, tenantID string) ([]*Policy, error)
	Update(ctx context.Context, policy *Policy) error
	Delete(ctx context.Context, id string) error
}