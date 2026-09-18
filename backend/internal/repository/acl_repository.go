package repository

import (
	"context"
	"errors"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type aclRepository struct {
	db *gorm.DB
}

func NewACLRepository(db *gorm.DB) domain.ACLRepository {
	return &aclRepository{db: db}
}

func (r *aclRepository) Create(ctx context.Context, acl *domain.ACLPermission) error {
	m := toACLModel(acl)
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return domain.ErrACLAlreadyExists
		}
		return err
	}
	acl.ID = m.ID
	acl.CreatedAt = m.CreatedAt
	acl.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *aclRepository) FindByID(ctx context.Context, id string) (*domain.ACLPermission, error) {
	var m aclModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrACLNotFound
		}
		return nil, err
	}
	return fromACLModel(&m), nil
}

func (r *aclRepository) FindBySubject(ctx context.Context, tenantID, subjectType, subjectID string) ([]*domain.ACLPermission, error) {
	var models []aclModel
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND subject_type = ? AND subject_id = ?", tenantID, subjectType, subjectID).
		Find(&models).Error; err != nil {
		return nil, err
	}
	acls := make([]*domain.ACLPermission, 0, len(models))
	for i := range models {
		acls = append(acls, fromACLModel(&models[i]))
	}
	return acls, nil
}

func (r *aclRepository) FindByResource(ctx context.Context, tenantID, resourceType, resourceID string) ([]*domain.ACLPermission, error) {
	var models []aclModel
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND resource_type = ? AND resource_id = ?", tenantID, resourceType, resourceID).
		Find(&models).Error; err != nil {
		return nil, err
	}
	acls := make([]*domain.ACLPermission, 0, len(models))
	for i := range models {
		acls = append(acls, fromACLModel(&models[i]))
	}
	return acls, nil
}

func (r *aclRepository) CheckPermission(ctx context.Context, tenantID, subjectType, subjectID, resourceType, resourceID, permission string) (*domain.ACLPermission, error) {
	var m aclModel
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND subject_type = ? AND subject_id = ? AND resource_type = ? AND resource_id = ? AND permission = ?",
			tenantID, subjectType, subjectID, resourceType, resourceID, permission).
		First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrACLNotFound
		}
		return nil, err
	}
	return fromACLModel(&m), nil
}

func (r *aclRepository) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&aclModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrACLNotFound
	}
	return nil
}

func (r *aclRepository) DeleteBySubjectAndResource(ctx context.Context, tenantID, subjectType, subjectID, resourceType, resourceID string) error {
	return r.db.WithContext(ctx).
		Where("tenant_id = ? AND subject_type = ? AND subject_id = ? AND resource_type = ? AND resource_id = ?",
			tenantID, subjectType, subjectID, resourceType, resourceID).
		Delete(&aclModel{}).Error
}

func toACLModel(acl *domain.ACLPermission) *aclModel {
	return &aclModel{
		ID:           acl.ID,
		TenantID:     acl.TenantID,
		SubjectType:  acl.SubjectType,
		SubjectID:    acl.SubjectID,
		ResourceType: acl.ResourceType,
		ResourceID:   acl.ResourceID,
		Permission:   acl.Permission,
		Effect:       acl.Effect,
	}
}

func fromACLModel(m *aclModel) *domain.ACLPermission {
	return &domain.ACLPermission{
		ID:           m.ID,
		TenantID:     m.TenantID,
		SubjectType:  m.SubjectType,
		SubjectID:    m.SubjectID,
		ResourceType: m.ResourceType,
		ResourceID:   m.ResourceID,
		Permission:   m.Permission,
		Effect:       m.Effect,
		CreatedAt:    m.CreatedAt,
		UpdatedAt:    m.UpdatedAt,
	}
}