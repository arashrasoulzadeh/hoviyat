package service

import (
	"context"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

// TenantService implements the tenant provisioning API (PRD §6: "Tenant
// provisioning API (create/suspend/delete tenant)").
type TenantService struct {
	tenants domain.TenantRepository
}

func NewTenantService(tenants domain.TenantRepository) *TenantService {
	return &TenantService{tenants: tenants}
}

// Create creates a new tenant with pending status (for self-service signup).
// Platform operators can create active tenants directly.
func (s *TenantService) Create(ctx context.Context, name, slug string) (*domain.Tenant, error) {
	tenant := &domain.Tenant{
		Name:   name,
		Slug:   slug,
		Status: domain.TenantStatusPending,
	}
	if err := s.tenants.Create(ctx, tenant); err != nil {
		return nil, err
	}
	return tenant, nil
}

// CreateActive creates a new tenant with active status (platform operator use).
func (s *TenantService) CreateActive(ctx context.Context, name, slug string) (*domain.Tenant, error) {
	tenant := &domain.Tenant{
		Name:   name,
		Slug:   slug,
		Status: domain.TenantStatusActive,
	}
	if err := s.tenants.Create(ctx, tenant); err != nil {
		return nil, err
	}
	return tenant, nil
}

// Activate activates a pending tenant (e.g., after email verification).
func (s *TenantService) Activate(ctx context.Context, tenantID string) error {
	return s.tenants.UpdateStatus(ctx, tenantID, domain.TenantStatusActive)
}

func (s *TenantService) Suspend(ctx context.Context, tenantID string) error {
	return s.tenants.UpdateStatus(ctx, tenantID, domain.TenantStatusSuspended)
}

func (s *TenantService) Reactivate(ctx context.Context, tenantID string) error {
	return s.tenants.UpdateStatus(ctx, tenantID, domain.TenantStatusActive)
}

func (s *TenantService) Delete(ctx context.Context, tenantID string) error {
	return s.tenants.Delete(ctx, tenantID)
}

func (s *TenantService) GetBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	return s.tenants.FindBySlug(ctx, slug)
}
