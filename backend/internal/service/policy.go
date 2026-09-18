package service

import (
	"context"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

type PolicyService struct {
	policies domain.PolicyRepository
}

func NewPolicyService(policies domain.PolicyRepository) *PolicyService {
	return &PolicyService{policies: policies}
}

func (s *PolicyService) Create(ctx context.Context, tenantID, name, description, rego string) (*domain.Policy, error) {
	policy := &domain.Policy{
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		Rego:        rego,
		Version:     1,
		IsActive:    false,
	}
	if err := s.policies.Create(ctx, policy); err != nil {
		return nil, err
	}
	return policy, nil
}

func (s *PolicyService) Get(ctx context.Context, id string) (*domain.Policy, error) {
	return s.policies.FindByID(ctx, id)
}

func (s *PolicyService) GetByName(ctx context.Context, tenantID, name string) (*domain.Policy, error) {
	return s.policies.FindByName(ctx, tenantID, name)
}

func (s *PolicyService) List(ctx context.Context, tenantID string) ([]*domain.Policy, error) {
	return s.policies.ListByTenant(ctx, tenantID)
}

func (s *PolicyService) ListActive(ctx context.Context, tenantID string) ([]*domain.Policy, error) {
	return s.policies.FindActiveByTenant(ctx, tenantID)
}

func (s *PolicyService) Update(ctx context.Context, policy *domain.Policy) error {
	// Increment version on update
	policy.Version++
	return s.policies.Update(ctx, policy)
}

func (s *PolicyService) Activate(ctx context.Context, tenantID, policyID string) error {
	// Deactivate all other policies for this tenant
	// (In production, you might want to allow multiple active policies)
	policies, err := s.policies.ListByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, p := range policies {
		if p.ID == policyID {
			p.IsActive = true
			if err := s.policies.Update(ctx, p); err != nil {
				return err
			}
		} else if p.IsActive {
			p.IsActive = false
			if err := s.policies.Update(ctx, p); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *PolicyService) Deactivate(ctx context.Context, policyID string) error {
	policy, err := s.policies.FindByID(ctx, policyID)
	if err != nil {
		return err
	}
	policy.IsActive = false
	return s.policies.Update(ctx, policy)
}

func (s *PolicyService) Delete(ctx context.Context, id string) error {
	return s.policies.Delete(ctx, id)
}

type PolicyEvaluationInput struct {
	User      map[string]interface{}
	Resource  map[string]interface{}
	Action    string
	Context   map[string]interface{}
}