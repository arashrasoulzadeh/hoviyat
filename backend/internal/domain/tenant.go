package domain

import (
	"context"
	"errors"
	"time"
)

type TenantStatus string

const (
	TenantStatusPending   TenantStatus = "pending"
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
)

// Tenant is the first-class organization entity all roles, policies, and
// audit logs are scoped to (PRD §6 "Multi-tenancy").
type Tenant struct {
	ID        string
	Name      string
	Slug      string
	Status    TenantStatus
	CreatedAt time.Time
	UpdatedAt time.Time
}

var (
	ErrTenantNotFound      = errors.New("tenant not found")
	ErrTenantAlreadyExists = errors.New("tenant already exists")
	ErrTenantSuspended     = errors.New("tenant is suspended")
)

type TenantRepository interface {
	Create(ctx context.Context, tenant *Tenant) error
	FindByID(ctx context.Context, id string) (*Tenant, error)
	FindBySlug(ctx context.Context, slug string) (*Tenant, error)
	UpdateStatus(ctx context.Context, id string, status TenantStatus) error
	Delete(ctx context.Context, id string) error
}
