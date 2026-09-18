package repository

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type samlProviderRepository struct {
	db *gorm.DB
}

func NewSAMLProviderRepository(db *gorm.DB) domain.SAMLProviderRepository {
	return &samlProviderRepository{db: db}
}

func (r *samlProviderRepository) Create(ctx context.Context, p *domain.SAMLProvider) error {
	attrJSON, _ := json.Marshal(p.AttributeMapping)
	m := &samlProviderModel{
		ID:               p.ID,
		TenantID:         p.TenantID,
		Name:             p.Name,
		EntityID:         p.EntityID,
		SSOURL:           p.SSOURL,
		SLOURL:           p.SLOURL,
		X509Cert:         p.X509Cert,
		PrivateKey:       p.PrivateKey,
		AttributeMapping: string(attrJSON),
		Enabled:          p.Enabled,
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return err
	}
	p.ID = m.ID
	p.CreatedAt = m.CreatedAt
	p.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *samlProviderRepository) FindByID(ctx context.Context, id string) (*domain.SAMLProvider, error) {
	var m samlProviderModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrSAMLProviderNotFound
		}
		return nil, err
	}
	return fromSAMLProviderModel(&m), nil
}

func (r *samlProviderRepository) FindByTenant(ctx context.Context, tenantID string) ([]*domain.SAMLProvider, error) {
	var models []samlProviderModel
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&models).Error; err != nil {
		return nil, err
	}
	providers := make([]*domain.SAMLProvider, 0, len(models))
	for i := range models {
		providers = append(providers, fromSAMLProviderModel(&models[i]))
	}
	return providers, nil
}

func (r *samlProviderRepository) Update(ctx context.Context, p *domain.SAMLProvider) error {
	attrJSON, _ := json.Marshal(p.AttributeMapping)
	m := &samlProviderModel{
		ID:               p.ID,
		TenantID:         p.TenantID,
		Name:             p.Name,
		EntityID:         p.EntityID,
		SSOURL:           p.SSOURL,
		SLOURL:           p.SLOURL,
		X509Cert:         p.X509Cert,
		PrivateKey:       p.PrivateKey,
		AttributeMapping: string(attrJSON),
		Enabled:          p.Enabled,
	}
	res := r.db.WithContext(ctx).Model(&samlProviderModel{}).Where("id = ?", p.ID).Updates(m)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrSAMLProviderNotFound
	}
	return nil
}

func (r *samlProviderRepository) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&samlProviderModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrSAMLProviderNotFound
	}
	return nil
}

func fromSAMLProviderModel(m *samlProviderModel) *domain.SAMLProvider {
	var attr map[string]string
	if m.AttributeMapping != "" {
		json.Unmarshal([]byte(m.AttributeMapping), &attr)
	}
	return &domain.SAMLProvider{
		ID:               m.ID,
		TenantID:         m.TenantID,
		Name:             m.Name,
		EntityID:         m.EntityID,
		SSOURL:           m.SSOURL,
		SLOURL:           m.SLOURL,
		X509Cert:         m.X509Cert,
		PrivateKey:       m.PrivateKey,
		AttributeMapping: attr,
		Enabled:          m.Enabled,
		CreatedAt:        m.CreatedAt,
		UpdatedAt:        m.UpdatedAt,
	}
}