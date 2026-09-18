package repository

import (
	"context"
	"errors"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type permissionRepository struct {
	db *gorm.DB
}

func NewPermissionRepository(db *gorm.DB) domain.PermissionRepository {
	return &permissionRepository{db: db}
}

func (r *permissionRepository) Create(ctx context.Context, perm *domain.Permission) error {
	m := toPermissionModel(perm)
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return domain.ErrACLAlreadyExists
		}
		return err
	}
	perm.ID = m.ID
	perm.CreatedAt = m.CreatedAt
	return nil
}

func (r *permissionRepository) FindByID(ctx context.Context, id string) (*domain.Permission, error) {
	var m permissionModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrACLNotFound
		}
		return nil, err
	}
	return fromPermissionModel(&m), nil
}

func (r *permissionRepository) FindByTenant(ctx context.Context, tenantID string) ([]*domain.Permission, error) {
	var models []permissionModel
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&models).Error; err != nil {
		return nil, err
	}
	perms := make([]*domain.Permission, 0, len(models))
	for i := range models {
		perms = append(perms, fromPermissionModel(&models[i]))
	}
	return perms, nil
}

func (r *permissionRepository) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&permissionModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrACLNotFound
	}
	return nil
}

func toPermissionModel(perm *domain.Permission) *permissionModel {
	return &permissionModel{
		ID:          perm.ID,
		TenantID:    perm.TenantID,
		Name:        perm.Name,
		Description: perm.Description,
	}
}

func fromPermissionModel(m *permissionModel) *domain.Permission {
	return &domain.Permission{
		ID:          m.ID,
		TenantID:    m.TenantID,
		Name:        m.Name,
		Description: m.Description,
		CreatedAt:   m.CreatedAt,
	}
}