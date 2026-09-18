package repository

import (
	"context"
	"errors"
	"strings"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type teamRepository struct {
	db *gorm.DB
}

func NewTeamRepository(db *gorm.DB) domain.TeamRepository {
	return &teamRepository{db: db}
}

func (r *teamRepository) Create(ctx context.Context, team *domain.Team) error {
	m := &teamModel{
		ID:       team.ID,
		TenantID: team.TenantID,
		Name:     team.Name,
		Slug:     team.Slug,
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return domain.ErrTeamAlreadyExists
		}
		return err
	}
	team.ID = m.ID
	team.CreatedAt = m.CreatedAt
	team.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *teamRepository) FindByID(ctx context.Context, id string) (*domain.Team, error) {
	var m teamModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrTeamNotFound
		}
		return nil, err
	}
	return fromTeamModel(&m), nil
}

func (r *teamRepository) FindBySlug(ctx context.Context, tenantID, slug string) (*domain.Team, error) {
	var m teamModel
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND slug = ?", tenantID, slug).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrTeamNotFound
		}
		return nil, err
	}
	return fromTeamModel(&m), nil
}

func (r *teamRepository) ListByTenant(ctx context.Context, tenantID string) ([]*domain.Team, error) {
	var models []teamModel
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&models).Error; err != nil {
		return nil, err
	}
	teams := make([]*domain.Team, 0, len(models))
	for i := range models {
		teams = append(teams, fromTeamModel(&models[i]))
	}
	return teams, nil
}

func (r *teamRepository) Update(ctx context.Context, team *domain.Team) error {
	m := &teamModel{
		ID:       team.ID,
		TenantID: team.TenantID,
		Name:     team.Name,
		Slug:     team.Slug,
	}
	res := r.db.WithContext(ctx).Model(&teamModel{}).Where("id = ?", team.ID).Updates(m)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrTeamNotFound
	}
	return nil
}

func (r *teamRepository) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&teamModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrTeamNotFound
	}
	return nil
}

func fromTeamModel(m *teamModel) *domain.Team {
	return &domain.Team{
		ID:        m.ID,
		TenantID:  m.TenantID,
		Name:      m.Name,
		Slug:      m.Slug,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}

type teamMembershipRepository struct {
	db *gorm.DB
}

func NewTeamMembershipRepository(db *gorm.DB) domain.TeamMembershipRepository {
	return &teamMembershipRepository{db: db}
}

func (r *teamMembershipRepository) Create(ctx context.Context, tm *domain.TeamMembership) error {
	m := toTeamMembershipModel(tm)
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return domain.ErrTeamMembershipAlreadyExists
		}
		return err
	}
	tm.CreatedAt = m.CreatedAt
	tm.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *teamMembershipRepository) FindByUserAndTeam(ctx context.Context, userID, teamID string) (*domain.TeamMembership, error) {
	var m teamMembershipModel
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND team_id = ?", userID, teamID).
		First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrTeamMembershipNotFound
		}
		return nil, err
	}
	return fromTeamMembershipModel(&m), nil
}

func (r *teamMembershipRepository) ListByUser(ctx context.Context, userID string) ([]*domain.TeamMembership, error) {
	var models []teamMembershipModel
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&models).Error; err != nil {
		return nil, err
	}
	tms := make([]*domain.TeamMembership, 0, len(models))
	for i := range models {
		tms = append(tms, fromTeamMembershipModel(&models[i]))
	}
	return tms, nil
}

func (r *teamMembershipRepository) ListByTeam(ctx context.Context, teamID string) ([]*domain.TeamMembership, error) {
	var models []teamMembershipModel
	if err := r.db.WithContext(ctx).Where("team_id = ?", teamID).Find(&models).Error; err != nil {
		return nil, err
	}
	tms := make([]*domain.TeamMembership, 0, len(models))
	for i := range models {
		tms = append(tms, fromTeamMembershipModel(&models[i]))
	}
	return tms, nil
}

func (r *teamMembershipRepository) UpdateRoles(ctx context.Context, userID, teamID string, roles []string) error {
	res := r.db.WithContext(ctx).Model(&teamMembershipModel{}).
		Where("user_id = ? AND team_id = ?", userID, teamID).
		Update("roles", strings.Join(roles, ","))
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrTeamMembershipNotFound
	}
	return nil
}

func (r *teamMembershipRepository) Delete(ctx context.Context, userID, teamID string) error {
	res := r.db.WithContext(ctx).
		Where("user_id = ? AND team_id = ?", userID, teamID).
		Delete(&teamMembershipModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrTeamMembershipNotFound
	}
	return nil
}

func toTeamMembershipModel(tm *domain.TeamMembership) *teamMembershipModel {
	return &teamMembershipModel{
		UserID: tm.UserID,
		TeamID: tm.TeamID,
		Roles:  strings.Join(tm.Roles, ","),
	}
}

func fromTeamMembershipModel(m *teamMembershipModel) *domain.TeamMembership {
	var roles []string
	if m.Roles != "" {
		roles = strings.Split(m.Roles, ",")
	}
	return &domain.TeamMembership{
		UserID:    m.UserID,
		TeamID:    m.TeamID,
		Roles:     roles,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}