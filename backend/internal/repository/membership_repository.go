package repository

import (
	"context"
	"errors"
	"strings"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type membershipRepository struct {
	db *gorm.DB
}

// NewMembershipRepository returns a domain.MembershipRepository backed by
// GORM/Postgres. Every query is scoped by (user_id, tenant_id) so a user's
// permissions in one tenant can never leak into another (PRD §6).
func NewMembershipRepository(db *gorm.DB) domain.MembershipRepository {
	return &membershipRepository{db: db}
}

func (r *membershipRepository) Create(ctx context.Context, membership *domain.Membership) error {
	m := toMembershipModel(membership)
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return domain.ErrMembershipAlreadyExists
		}
		return err
	}
	membership.CreatedAt = m.CreatedAt
	membership.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *membershipRepository) FindByUserAndTenant(ctx context.Context, userID, tenantID string) (*domain.Membership, error) {
	var m membershipModel
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND tenant_id = ?", userID, tenantID).
		First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrMembershipNotFound
		}
		return nil, err
	}
	return fromMembershipModel(&m), nil
}

func (r *membershipRepository) ListByUser(ctx context.Context, userID string) ([]*domain.Membership, error) {
	var models []membershipModel
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&models).Error; err != nil {
		return nil, err
	}
	memberships := make([]*domain.Membership, 0, len(models))
	for i := range models {
		memberships = append(memberships, fromMembershipModel(&models[i]))
	}
	return memberships, nil
}

func (r *membershipRepository) UpdateRoles(ctx context.Context, userID, tenantID string, roles []string) error {
	res := r.db.WithContext(ctx).Model(&membershipModel{}).
		Where("user_id = ? AND tenant_id = ?", userID, tenantID).
		Update("roles", strings.Join(roles, ","))
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrMembershipNotFound
	}
	return nil
}

func (r *membershipRepository) Delete(ctx context.Context, userID, tenantID string) error {
	res := r.db.WithContext(ctx).
		Where("user_id = ? AND tenant_id = ?", userID, tenantID).
		Delete(&membershipModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrMembershipNotFound
	}
	return nil
}

func toMembershipModel(m *domain.Membership) *membershipModel {
	return &membershipModel{
		UserID:   m.UserID,
		TenantID: m.TenantID,
		Roles:    strings.Join(m.Roles, ","),
	}
}

func fromMembershipModel(m *membershipModel) *domain.Membership {
	var roles []string
	if m.Roles != "" {
		roles = strings.Split(m.Roles, ",")
	}
	return &domain.Membership{
		UserID:    m.UserID,
		TenantID:  m.TenantID,
		Roles:     roles,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}
