package repository

import (
	"context"
	"errors"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type rolePermissionRepository struct {
	db *gorm.DB
}

func NewRolePermissionRepository(db *gorm.DB) domain.RolePermissionRepository {
	return &rolePermissionRepository{db: db}
}

func (r *rolePermissionRepository) Create(ctx context.Context, rp *domain.RolePermission) error {
	m := toRolePermissionModel(rp)
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return domain.ErrACLAlreadyExists // reuse for now
		}
		return err
	}
	rp.ID = m.ID
	rp.CreatedAt = m.CreatedAt
	return nil
}

func (r *rolePermissionRepository) FindByRole(ctx context.Context, tenantID, roleName string) ([]*domain.RolePermission, error) {
	var models []rolePermissionModel
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND role_name = ?", tenantID, roleName).
		Find(&models).Error; err != nil {
		return nil, err
	}
	rps := make([]*domain.RolePermission, 0, len(models))
	for i := range models {
		rps = append(rps, fromRolePermissionModel(&models[i]))
	}
	return rps, nil
}

func (r *rolePermissionRepository) FindByTenant(ctx context.Context, tenantID string) ([]*domain.RolePermission, error) {
	var models []rolePermissionModel
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Find(&models).Error; err != nil {
		return nil, err
	}
	rps := make([]*domain.RolePermission, 0, len(models))
	for i := range models {
		rps = append(rps, fromRolePermissionModel(&models[i]))
	}
	return rps, nil
}

func (r *rolePermissionRepository) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&rolePermissionModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrACLNotFound
	}
	return nil
}

func (r *rolePermissionRepository) DeleteByRole(ctx context.Context, tenantID, roleName string) error {
	return r.db.WithContext(ctx).
		Where("tenant_id = ? AND role_name = ?", tenantID, roleName).
		Delete(&rolePermissionModel{}).Error
}

func toRolePermissionModel(rp *domain.RolePermission) *rolePermissionModel {
	return &rolePermissionModel{
		ID:         rp.ID,
		TenantID:   rp.TenantID,
		RoleName:   rp.RoleName,
		Permission: rp.Permission,
	}
}

func fromRolePermissionModel(m *rolePermissionModel) *domain.RolePermission {
	return &domain.RolePermission{
		ID:         m.ID,
		TenantID:   m.TenantID,
		RoleName:   m.RoleName,
		Permission: m.Permission,
		CreatedAt:  m.CreatedAt,
	}
}