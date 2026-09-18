package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type oauth2ClientRepository struct {
	db *gorm.DB
}

func NewOAuth2ClientRepository(db *gorm.DB) domain.OAuth2ClientRepository {
	return &oauth2ClientRepository{db: db}
}

func (r *oauth2ClientRepository) Create(ctx context.Context, c *domain.OAuth2Client) error {
	redirectURIs, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.Scopes)
	grantTypes, _ := json.Marshal(c.GrantTypes)
	responseTypes, _ := json.Marshal(c.ResponseTypes)
	contacts, _ := json.Marshal(c.Contacts)

	m := &oauth2ClientModel{
		ID:                      c.ID,
		TenantID:                c.TenantID,
		Name:                    c.Name,
		ClientID:                c.ClientID,
		ClientSecretHash:        c.ClientSecret,
		RedirectURIs:            string(redirectURIs),
		Scopes:                  string(scopes),
		GrantTypes:              string(grantTypes),
		ResponseTypes:           string(responseTypes),
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		LogoURI:                 c.LogoURI,
		ClientURI:               c.ClientURI,
		PolicyURI:               c.PolicyURI,
		TOSURI:                  c.TOSURI,
		JWKSURI:                 c.JWKSURI,
		Contacts:                string(contacts),
		Enabled:                 c.Enabled,
		CreatedBy:               c.CreatedBy,
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return domain.ErrOAuth2ClientNotFound
		}
		return err
	}
	c.ID = m.ID
	c.CreatedAt = m.CreatedAt
	c.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *oauth2ClientRepository) FindByID(ctx context.Context, id string) (*domain.OAuth2Client, error) {
	var m oauth2ClientModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrOAuth2ClientNotFound
		}
		return nil, err
	}
	return fromOAuth2ClientModel(&m), nil
}

func (r *oauth2ClientRepository) FindByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error) {
	var m oauth2ClientModel
	if err := r.db.WithContext(ctx).Where("client_id = ?", clientID).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrOAuth2ClientNotFound
		}
		return nil, err
	}
	return fromOAuth2ClientModel(&m), nil
}

func (r *oauth2ClientRepository) FindByTenant(ctx context.Context, tenantID string) ([]*domain.OAuth2Client, error) {
	var models []oauth2ClientModel
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&models).Error; err != nil {
		return nil, err
	}
	clients := make([]*domain.OAuth2Client, 0, len(models))
	for i := range models {
		clients = append(clients, fromOAuth2ClientModel(&models[i]))
	}
	return clients, nil
}

func (r *oauth2ClientRepository) Update(ctx context.Context, c *domain.OAuth2Client) error {
	redirectURIs, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.Scopes)
	grantTypes, _ := json.Marshal(c.GrantTypes)
	responseTypes, _ := json.Marshal(c.ResponseTypes)
	contacts, _ := json.Marshal(c.Contacts)

	m := &oauth2ClientModel{
		ID:                      c.ID,
		TenantID:                c.TenantID,
		Name:                    c.Name,
		ClientID:                c.ClientID,
		ClientSecretHash:        c.ClientSecret,
		RedirectURIs:            string(redirectURIs),
		Scopes:                  string(scopes),
		GrantTypes:              string(grantTypes),
		ResponseTypes:           string(responseTypes),
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		LogoURI:                 c.LogoURI,
		ClientURI:               c.ClientURI,
		PolicyURI:               c.PolicyURI,
		TOSURI:                  c.TOSURI,
		JWKSURI:                 c.JWKSURI,
		Contacts:                string(contacts),
		Enabled:                 c.Enabled,
	}
	res := r.db.WithContext(ctx).Model(&oauth2ClientModel{}).Where("id = ?", c.ID).Updates(m)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrOAuth2ClientNotFound
	}
	return nil
}

func (r *oauth2ClientRepository) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&oauth2ClientModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrOAuth2ClientNotFound
	}
	return nil
}

func fromOAuth2ClientModel(m *oauth2ClientModel) *domain.OAuth2Client {
	var redirectURIs, scopes, grantTypes, responseTypes, contacts []string
	json.Unmarshal([]byte(m.RedirectURIs), &redirectURIs)
	json.Unmarshal([]byte(m.Scopes), &scopes)
	json.Unmarshal([]byte(m.GrantTypes), &grantTypes)
	json.Unmarshal([]byte(m.ResponseTypes), &responseTypes)
	json.Unmarshal([]byte(m.Contacts), &contacts)

	return &domain.OAuth2Client{
		ID:                      m.ID,
		TenantID:                m.TenantID,
		Name:                    m.Name,
		ClientID:                m.ClientID,
		ClientSecret:            m.ClientSecretHash,
		RedirectURIs:            redirectURIs,
		Scopes:                  scopes,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: m.TokenEndpointAuthMethod,
		LogoURI:                 m.LogoURI,
		ClientURI:               m.ClientURI,
		PolicyURI:               m.PolicyURI,
		TOSURI:                  m.TOSURI,
		JWKSURI:                 m.JWKSURI,
		Contacts:                contacts,
		Enabled:                 m.Enabled,
		CreatedAt:               m.CreatedAt,
		UpdatedAt:               m.UpdatedAt,
		CreatedBy:               m.CreatedBy,
	}
}

type oauth2AuthCodeRepository struct {
	db *gorm.DB
}

func NewOAuth2AuthCodeRepository(db *gorm.DB) domain.OAuth2AuthorizationCodeRepository {
	return &oauth2AuthCodeRepository{db: db}
}

func (r *oauth2AuthCodeRepository) Create(ctx context.Context, c *domain.OAuth2AuthorizationCode) error {
	scopes, _ := json.Marshal(c.Scopes)
	m := &oauth2AuthCodeModel{
		ID:                   c.ID,
		ClientID:             c.ClientID,
		UserID:               c.UserID,
		TenantID:             c.TenantID,
		RedirectURI:          c.RedirectURI,
		Scopes:               string(scopes),
		CodeChallenge:        c.CodeChallenge,
		CodeChallengeMethod:  c.CodeChallengeMethod,
		Nonce:                c.Nonce,
		ExpiresAt:            c.ExpiresAt,
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return err
	}
	c.ID = m.ID
	c.CreatedAt = m.CreatedAt
	return nil
}

func (r *oauth2AuthCodeRepository) FindByCode(ctx context.Context, code string) (*domain.OAuth2AuthorizationCode, error) {
	var m oauth2AuthCodeModel
	if err := r.db.WithContext(ctx).Where("id = ?", code).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if time.Now().After(m.ExpiresAt) {
		r.db.WithContext(ctx).Delete(&m)
		return nil, nil
	}
	return fromOAuth2AuthCodeModel(&m), nil
}

func (r *oauth2AuthCodeRepository) Delete(ctx context.Context, code string) error {
	return r.db.WithContext(ctx).Where("id = ?", code).Delete(&oauth2AuthCodeModel{}).Error
}

func (r *oauth2AuthCodeRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&oauth2AuthCodeModel{}).Error
}

func fromOAuth2AuthCodeModel(m *oauth2AuthCodeModel) *domain.OAuth2AuthorizationCode {
	var scopes []string
	json.Unmarshal([]byte(m.Scopes), &scopes)
	return &domain.OAuth2AuthorizationCode{
		ID:                  m.ID,
		ClientID:            m.ClientID,
		UserID:              m.UserID,
		TenantID:            m.TenantID,
		RedirectURI:         m.RedirectURI,
		Scopes:              scopes,
		CodeChallenge:       m.CodeChallenge,
		CodeChallengeMethod: m.CodeChallengeMethod,
		Nonce:               m.Nonce,
		ExpiresAt:           m.ExpiresAt,
		CreatedAt:           m.CreatedAt,
	}
}

type oauth2ConsentRepository struct {
	db *gorm.DB
}

func NewOAuth2ConsentRepository(db *gorm.DB) domain.OAuth2ConsentRepository {
	return &oauth2ConsentRepository{db: db}
}

func (r *oauth2ConsentRepository) Create(ctx context.Context, c *domain.OAuth2Consent) error {
	scopes, _ := json.Marshal(c.Scopes)
	m := &oauth2ConsentModel{
		ID:        c.ID,
		UserID:    c.UserID,
		ClientID:  c.ClientID,
		TenantID:  c.TenantID,
		Scopes:    string(scopes),
		ExpiresAt: c.ExpiresAt,
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return err
	}
	c.ID = m.ID
	c.CreatedAt = m.CreatedAt
	c.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *oauth2ConsentRepository) FindByUserAndClient(ctx context.Context, userID, clientID string) (*domain.OAuth2Consent, error) {
	var m oauth2ConsentModel
	if err := r.db.WithContext(ctx).Where("user_id = ? AND client_id = ?", userID, clientID).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if m.ExpiresAt != nil && time.Now().After(*m.ExpiresAt) {
		return nil, nil
	}
	return fromOAuth2ConsentModel(&m), nil
}

func (r *oauth2ConsentRepository) FindByUser(ctx context.Context, userID string) ([]*domain.OAuth2Consent, error) {
	var models []oauth2ConsentModel
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&models).Error; err != nil {
		return nil, err
	}
	consents := make([]*domain.OAuth2Consent, 0, len(models))
	for i := range models {
		if models[i].ExpiresAt != nil && time.Now().After(*models[i].ExpiresAt) {
			continue
		}
		consents = append(consents, fromOAuth2ConsentModel(&models[i]))
	}
	return consents, nil
}

func (r *oauth2ConsentRepository) Update(ctx context.Context, c *domain.OAuth2Consent) error {
	scopes, _ := json.Marshal(c.Scopes)
	m := &oauth2ConsentModel{
		ID:        c.ID,
		UserID:    c.UserID,
		ClientID:  c.ClientID,
		TenantID:  c.TenantID,
		Scopes:    string(scopes),
		ExpiresAt: c.ExpiresAt,
	}
	res := r.db.WithContext(ctx).Model(&oauth2ConsentModel{}).Where("id = ?", c.ID).Updates(m)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("consent not found")
	}
	return nil
}

func (r *oauth2ConsentRepository) Delete(ctx context.Context, userID, clientID string) error {
	return r.db.WithContext(ctx).Where("user_id = ? AND client_id = ?", userID, clientID).Delete(&oauth2ConsentModel{}).Error
}

func fromOAuth2ConsentModel(m *oauth2ConsentModel) *domain.OAuth2Consent {
	var scopes []string
	json.Unmarshal([]byte(m.Scopes), &scopes)
	return &domain.OAuth2Consent{
		ID:        m.ID,
		UserID:    m.UserID,
		ClientID:  m.ClientID,
		TenantID:  m.TenantID,
		Scopes:    scopes,
		ExpiresAt: m.ExpiresAt,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}

type signingKeyRepository struct {
	db *gorm.DB
}

func NewSigningKeyRepository(db *gorm.DB) domain.SigningKeyRepository {
	return &signingKeyRepository{db: db}
}

func (r *signingKeyRepository) Create(ctx context.Context, k *domain.SigningKey) error {
	m := &signingKeyModel{
		ID:         k.ID,
		KeyID:      k.KeyID,
		Algorithm:  k.Algorithm,
		PrivateKey: k.PrivateKey,
		PublicKey:  k.PublicKey,
		IsActive:   k.IsActive,
		ExpiresAt:  k.ExpiresAt,
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return err
	}
	k.ID = m.ID
	k.CreatedAt = m.CreatedAt
	return nil
}

func (r *signingKeyRepository) FindActive(ctx context.Context) (*domain.SigningKey, error) {
	var m signingKeyModel
	if err := r.db.WithContext(ctx).Where("is_active = ?", true).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if m.ExpiresAt != nil && time.Now().After(*m.ExpiresAt) {
		return nil, nil
	}
	return fromSigningKeyModel(&m), nil
}

func (r *signingKeyRepository) FindByID(ctx context.Context, id string) (*domain.SigningKey, error) {
	var m signingKeyModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return fromSigningKeyModel(&m), nil
}

func (r *signingKeyRepository) FindByKeyID(ctx context.Context, keyID string) (*domain.SigningKey, error) {
	var m signingKeyModel
	if err := r.db.WithContext(ctx).Where("key_id = ?", keyID).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return fromSigningKeyModel(&m), nil
}

func (r *signingKeyRepository) List(ctx context.Context) ([]*domain.SigningKey, error) {
	var models []signingKeyModel
	if err := r.db.WithContext(ctx).Find(&models).Error; err != nil {
		return nil, err
	}
	keys := make([]*domain.SigningKey, 0, len(models))
	for i := range models {
		keys = append(keys, fromSigningKeyModel(&models[i]))
	}
	return keys, nil
}

func (r *signingKeyRepository) Update(ctx context.Context, k *domain.SigningKey) error {
	m := &signingKeyModel{
		ID:         k.ID,
		KeyID:      k.KeyID,
		Algorithm:  k.Algorithm,
		PrivateKey: k.PrivateKey,
		PublicKey:  k.PublicKey,
		IsActive:   k.IsActive,
		ExpiresAt:  k.ExpiresAt,
	}
	res := r.db.WithContext(ctx).Model(&signingKeyModel{}).Where("id = ?", k.ID).Updates(m)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("signing key not found")
	}
	return nil
}

func fromSigningKeyModel(m *signingKeyModel) *domain.SigningKey {
	return &domain.SigningKey{
		ID:         m.ID,
		KeyID:      m.KeyID,
		Algorithm:  m.Algorithm,
		PrivateKey: m.PrivateKey,
		PublicKey:  m.PublicKey,
		IsActive:   m.IsActive,
		CreatedAt:  m.CreatedAt,
		ExpiresAt:  m.ExpiresAt,
	}
}