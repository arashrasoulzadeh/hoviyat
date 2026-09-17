package repository

import (
	"context"
	"errors"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type tenantRepository struct {
	db *gorm.DB
}

// NewTenantRepository returns a domain.TenantRepository backed by
// GORM/Postgres.
func NewTenantRepository(db *gorm.DB) domain.TenantRepository {
	return &tenantRepository{db: db}
}

func (r *tenantRepository) Create(ctx context.Context, tenant *domain.Tenant) error {
	if tenant.Status == "" {
		tenant.Status = domain.TenantStatusActive
	}
	m := &tenantModel{
		ID:     tenant.ID,
		Name:   tenant.Name,
		Slug:   tenant.Slug,
		Status: string(tenant.Status),
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return domain.ErrTenantAlreadyExists
		}
		return err
	}
	tenant.ID = m.ID
	tenant.CreatedAt = m.CreatedAt
	tenant.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *tenantRepository) FindByID(ctx context.Context, id string) (*domain.Tenant, error) {
	var m tenantModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrTenantNotFound
		}
		return nil, err
	}
	return fromTenantModel(&m), nil
}

func (r *tenantRepository) FindBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	var m tenantModel
	if err := r.db.WithContext(ctx).Where("slug = ?", slug).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrTenantNotFound
		}
		return nil, err
	}
	return fromTenantModel(&m), nil
}

func (r *tenantRepository) UpdateStatus(ctx context.Context, id string, status domain.TenantStatus) error {
	res := r.db.WithContext(ctx).Model(&tenantModel{}).Where("id = ?", id).Update("status", string(status))
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrTenantNotFound
	}
	return nil
}

func (r *tenantRepository) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&tenantModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrTenantNotFound
	}
	return nil
}

func fromTenantModel(m *tenantModel) *domain.Tenant {
	return &domain.Tenant{
		ID:        m.ID,
		Name:      m.Name,
		Slug:      m.Slug,
		Status:    domain.TenantStatus(m.Status),
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}
