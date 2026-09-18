package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type oauth2ProviderRepository struct {
	db *gorm.DB
}

func NewOAuth2ProviderRepository(db *gorm.DB) domain.OAuth2ProviderRepository {
	return &oauth2ProviderRepository{db: db}
}

func (r *oauth2ProviderRepository) Create(ctx context.Context, p *domain.OAuth2Provider) error {
	scopesJSON, _ := json.Marshal(p.Scopes)
	m := &oauth2ProviderModel{
		ID:            p.ID,
		TenantID:      p.TenantID,
		Name:          p.Name,
		ClientID:      p.ClientID,
		ClientSecret:  p.ClientSecret,
		AuthURL:       p.AuthURL,
		TokenURL:      p.TokenURL,
		UserInfoURL:   p.UserInfoURL,
		Scopes:        string(scopesJSON),
		IssuerURL:     p.IssuerURL,
		ProviderType:  p.ProviderType,
		Enabled:       p.Enabled,
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return domain.ErrOAuth2ProviderNotFound
		}
		return err
	}
	p.ID = m.ID
	p.CreatedAt = m.CreatedAt
	p.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *oauth2ProviderRepository) FindByID(ctx context.Context, id string) (*domain.OAuth2Provider, error) {
	var m oauth2ProviderModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrOAuth2ProviderNotFound
		}
		return nil, err
	}
	return fromOAuth2ProviderModel(&m), nil
}

func (r *oauth2ProviderRepository) FindByTenant(ctx context.Context, tenantID string) ([]*domain.OAuth2Provider, error) {
	var models []oauth2ProviderModel
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&models).Error; err != nil {
		return nil, err
	}
	providers := make([]*domain.OAuth2Provider, 0, len(models))
	for i := range models {
		providers = append(providers, fromOAuth2ProviderModel(&models[i]))
	}
	return providers, nil
}

func (r *oauth2ProviderRepository) FindByTenantAndName(ctx context.Context, tenantID, name string) (*domain.OAuth2Provider, error) {
	var m oauth2ProviderModel
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND name = ?", tenantID, name).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrOAuth2ProviderNotFound
		}
		return nil, err
	}
	return fromOAuth2ProviderModel(&m), nil
}

func (r *oauth2ProviderRepository) Update(ctx context.Context, p *domain.OAuth2Provider) error {
	scopesJSON, _ := json.Marshal(p.Scopes)
	m := &oauth2ProviderModel{
		ID:            p.ID,
		TenantID:      p.TenantID,
		Name:          p.Name,
		ClientID:      p.ClientID,
		ClientSecret:  p.ClientSecret,
		AuthURL:       p.AuthURL,
		TokenURL:      p.TokenURL,
		UserInfoURL:   p.UserInfoURL,
		Scopes:        string(scopesJSON),
		IssuerURL:     p.IssuerURL,
		ProviderType:  p.ProviderType,
		Enabled:       p.Enabled,
	}
	res := r.db.WithContext(ctx).Model(&oauth2ProviderModel{}).Where("id = ?", p.ID).Updates(m)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrOAuth2ProviderNotFound
	}
	return nil
}

func (r *oauth2ProviderRepository) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&oauth2ProviderModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrOAuth2ProviderNotFound
	}
	return nil
}

func fromOAuth2ProviderModel(m *oauth2ProviderModel) *domain.OAuth2Provider {
	var scopes []string
	if m.Scopes != "" {
		json.Unmarshal([]byte(m.Scopes), &scopes)
	}
	return &domain.OAuth2Provider{
		ID:            m.ID,
		TenantID:      m.TenantID,
		Name:          m.Name,
		ClientID:      m.ClientID,
		ClientSecret:  m.ClientSecret,
		AuthURL:       m.AuthURL,
		TokenURL:      m.TokenURL,
		UserInfoURL:   m.UserInfoURL,
		Scopes:        scopes,
		IssuerURL:     m.IssuerURL,
		ProviderType:  m.ProviderType,
		Enabled:       m.Enabled,
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
	}
}

type oauth2StateRepository struct {
	db *gorm.DB
}

func NewOAuth2StateRepository(db *gorm.DB) domain.OAuth2StateRepository {
	return &oauth2StateRepository{db: db}
}

func (r *oauth2StateRepository) Create(ctx context.Context, s *domain.OAuth2State) error {
	m := &oauth2StateModel{
		ID:                  s.ID,
		State:               s.State,
		ProviderID:          s.ProviderID,
		TenantID:            s.TenantID,
		RedirectURI:         s.RedirectURI,
		CodeChallenge:       s.CodeChallenge,
		CodeChallengeMethod: s.CodeChallengeMethod,
		ExpiresAt:           s.ExpiresAt,
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return err
	}
	s.ID = m.ID
	s.CreatedAt = m.CreatedAt
	return nil
}

func (r *oauth2StateRepository) FindByState(ctx context.Context, state string) (*domain.OAuth2State, error) {
	var m oauth2StateModel
	if err := r.db.WithContext(ctx).Where("state = ?", state).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // not an error, just not found
		}
		return nil, err
	}
	return fromOAuth2StateModel(&m), nil
}

func (r *oauth2StateRepository) Delete(ctx context.Context, state string) error {
	return r.db.WithContext(ctx).Where("state = ?", state).Delete(&oauth2StateModel{}).Error
}

func (r *oauth2StateRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&oauth2StateModel{}).Error
}

func fromOAuth2StateModel(m *oauth2StateModel) *domain.OAuth2State {
	return &domain.OAuth2State{
		ID:                  m.ID,
		State:               m.State,
		ProviderID:          m.ProviderID,
		TenantID:            m.TenantID,
		RedirectURI:         m.RedirectURI,
		CodeChallenge:       m.CodeChallenge,
		CodeChallengeMethod: m.CodeChallengeMethod,
		ExpiresAt:           m.ExpiresAt,
		CreatedAt:           m.CreatedAt,
	}
}