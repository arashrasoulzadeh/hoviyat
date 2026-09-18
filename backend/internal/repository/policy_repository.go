package repository

import (
	"context"
	"errors"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type policyRepository struct {
	db *gorm.DB
}

func NewPolicyRepository(db *gorm.DB) domain.PolicyRepository {
	return &policyRepository{db: db}
}

func (r *policyRepository) Create(ctx context.Context, policy *domain.Policy) error {
	m := toPolicyModel(policy)
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return domain.ErrACLAlreadyExists
		}
		return err
	}
	policy.ID = m.ID
	policy.CreatedAt = m.CreatedAt
	policy.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *policyRepository) FindByID(ctx context.Context, id string) (*domain.Policy, error) {
	var m policyModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrACLNotFound
		}
		return nil, err
	}
	return fromPolicyModel(&m), nil
}

func (r *policyRepository) FindByName(ctx context.Context, tenantID, name string) (*domain.Policy, error) {
	var m policyModel
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND name = ?", tenantID, name).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrACLNotFound
		}
		return nil, err
	}
	return fromPolicyModel(&m), nil
}

func (r *policyRepository) FindActiveByTenant(ctx context.Context, tenantID string) ([]*domain.Policy, error) {
	var models []policyModel
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND is_active = ?", tenantID, true).Find(&models).Error; err != nil {
		return nil, err
	}
	policies := make([]*domain.Policy, 0, len(models))
	for i := range models {
		policies = append(policies, fromPolicyModel(&models[i]))
	}
	return policies, nil
}

func (r *policyRepository) ListByTenant(ctx context.Context, tenantID string) ([]*domain.Policy, error) {
	var models []policyModel
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&models).Error; err != nil {
		return nil, err
	}
	policies := make([]*domain.Policy, 0, len(models))
	for i := range models {
		policies = append(policies, fromPolicyModel(&models[i]))
	}
	return policies, nil
}

func (r *policyRepository) Update(ctx context.Context, policy *domain.Policy) error {
	m := toPolicyModel(policy)
	res := r.db.WithContext(ctx).Model(&policyModel{}).Where("id = ?", policy.ID).Updates(m)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrACLNotFound
	}
	policy.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *policyRepository) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&policyModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrACLNotFound
	}
	return nil
}

func toPolicyModel(policy *domain.Policy) *policyModel {
	return &policyModel{
		ID:          policy.ID,
		TenantID:    policy.TenantID,
		Name:        policy.Name,
		Description: policy.Description,
		Rego:        policy.Rego,
		Version:     policy.Version,
		IsActive:    policy.IsActive,
	}
}

func fromPolicyModel(m *policyModel) *domain.Policy {
	return &domain.Policy{
		ID:          m.ID,
		TenantID:    m.TenantID,
		Name:        m.Name,
		Description: m.Description,
		Rego:        m.Rego,
		Version:     m.Version,
		IsActive:    m.IsActive,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}
}