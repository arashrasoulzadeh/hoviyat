package repository

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type mfaMethodRepository struct {
	db *gorm.DB
}

func NewMFAMethodRepository(db *gorm.DB) domain.MFAMethodRepository {
	return &mfaMethodRepository{db: db}
}

func (r *mfaMethodRepository) Create(ctx context.Context, m *domain.MFAMethod) error {
	backupJSON, _ := json.Marshal(m.BackupCodes)
	model := &mfaMethodModel{
		ID:         m.ID,
		UserID:     m.UserID,
		TenantID:   m.TenantID,
		Type:       m.Type,
		Name:       m.Name,
		Secret:     m.Secret,
		BackupCodes: string(backupJSON),
		IsPrimary:  m.IsPrimary,
		VerifiedAt: m.VerifiedAt,
		LastUsedAt: m.LastUsedAt,
	}
	if err := r.db.WithContext(ctx).Create(model).Error; err != nil {
		return err
	}
	m.ID = model.ID
	m.CreatedAt = model.CreatedAt
	m.UpdatedAt = model.UpdatedAt
	return nil
}

func (r *mfaMethodRepository) FindByID(ctx context.Context, id string) (*domain.MFAMethod, error) {
	var m mfaMethodModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrMFAMethodNotFound
		}
		return nil, err
	}
	return fromMFAMethodModel(&m), nil
}

func (r *mfaMethodRepository) FindByUser(ctx context.Context, userID string) ([]*domain.MFAMethod, error) {
	var models []mfaMethodModel
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&models).Error; err != nil {
		return nil, err
	}
	methods := make([]*domain.MFAMethod, 0, len(models))
	for i := range models {
		methods = append(methods, fromMFAMethodModel(&models[i]))
	}
	return methods, nil
}

func (r *mfaMethodRepository) FindPrimaryByUser(ctx context.Context, userID string) (*domain.MFAMethod, error) {
	var m mfaMethodModel
	if err := r.db.WithContext(ctx).Where("user_id = ? AND is_primary = ?", userID, true).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return fromMFAMethodModel(&m), nil
}

func (r *mfaMethodRepository) Update(ctx context.Context, m *domain.MFAMethod) error {
	backupJSON, _ := json.Marshal(m.BackupCodes)
	model := &mfaMethodModel{
		ID:          m.ID,
		UserID:      m.UserID,
		TenantID:    m.TenantID,
		Type:        m.Type,
		Name:        m.Name,
		Secret:      m.Secret,
		BackupCodes: string(backupJSON),
		IsPrimary:   m.IsPrimary,
		VerifiedAt:  m.VerifiedAt,
		LastUsedAt:  m.LastUsedAt,
	}
	res := r.db.WithContext(ctx).Model(&mfaMethodModel{}).Where("id = ?", m.ID).Updates(model)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrMFAMethodNotFound
	}
	return nil
}

func (r *mfaMethodRepository) Delete(ctx context.Context, id string) error {
	res := r.db.WithContext(ctx).Where("id = ?", id).Delete(&mfaMethodModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrMFAMethodNotFound
	}
	return nil
}

func fromMFAMethodModel(m *mfaMethodModel) *domain.MFAMethod {
	var backupCodes []string
	if m.BackupCodes != "" {
		json.Unmarshal([]byte(m.BackupCodes), &backupCodes)
	}
	return &domain.MFAMethod{
		ID:          m.ID,
		UserID:      m.UserID,
		TenantID:    m.TenantID,
		Type:        m.Type,
		Name:        m.Name,
		Secret:      m.Secret,
		BackupCodes: backupCodes,
		IsPrimary:   m.IsPrimary,
		VerifiedAt:  m.VerifiedAt,
		LastUsedAt:  m.LastUsedAt,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}
}

type webAuthnCredentialRepository struct {
	db *gorm.DB
}

func NewWebAuthnCredentialRepository(db *gorm.DB) domain.WebAuthnCredentialRepository {
	return &webAuthnCredentialRepository{db: db}
}

func (r *webAuthnCredentialRepository) Create(ctx context.Context, c *domain.WebAuthnCredential) error {
	transportJSON, _ := json.Marshal(c.Transport)
	model := &webAuthnCredentialModel{
		ID:              c.ID,
		UserID:          c.UserID,
		TenantID:        c.TenantID,
		CredentialID:    c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       string(transportJSON),
		SignCount:       c.SignCount,
		DeviceName:      c.DeviceName,
	}
	if err := r.db.WithContext(ctx).Create(model).Error; err != nil {
		return err
	}
	c.ID = model.ID
	c.CreatedAt = model.CreatedAt
	return nil
}

func (r *webAuthnCredentialRepository) FindByID(ctx context.Context, id string) (*domain.WebAuthnCredential, error) {
	var m webAuthnCredentialModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return fromWebAuthnCredentialModel(&m), nil
}

func (r *webAuthnCredentialRepository) FindByUser(ctx context.Context, userID string) ([]*domain.WebAuthnCredential, error) {
	var models []webAuthnCredentialModel
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&models).Error; err != nil {
		return nil, err
	}
	creds := make([]*domain.WebAuthnCredential, 0, len(models))
	for i := range models {
		creds = append(creds, fromWebAuthnCredentialModel(&models[i]))
	}
	return creds, nil
}

func (r *webAuthnCredentialRepository) FindByCredentialID(ctx context.Context, credentialID string) (*domain.WebAuthnCredential, error) {
	var m webAuthnCredentialModel
	if err := r.db.WithContext(ctx).Where("credential_id = ?", credentialID).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return fromWebAuthnCredentialModel(&m), nil
}

func (r *webAuthnCredentialRepository) Update(ctx context.Context, c *domain.WebAuthnCredential) error {
	transportJSON, _ := json.Marshal(c.Transport)
	model := &webAuthnCredentialModel{
		ID:              c.ID,
		UserID:          c.UserID,
		TenantID:        c.TenantID,
		CredentialID:    c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       string(transportJSON),
		SignCount:       c.SignCount,
		DeviceName:      c.DeviceName,
		LastUsedAt:      c.LastUsedAt,
	}
	res := r.db.WithContext(ctx).Model(&webAuthnCredentialModel{}).Where("id = ?", c.ID).Updates(model)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return nil
	}
	return nil
}

func (r *webAuthnCredentialRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&webAuthnCredentialModel{}).Error
}

func fromWebAuthnCredentialModel(m *webAuthnCredentialModel) *domain.WebAuthnCredential {
	var transport []string
	if m.Transport != "" {
		json.Unmarshal([]byte(m.Transport), &transport)
	}
	return &domain.WebAuthnCredential{
		ID:              m.ID,
		UserID:          m.UserID,
		TenantID:        m.TenantID,
		CredentialID:    m.CredentialID,
		PublicKey:       m.PublicKey,
		AttestationType: m.AttestationType,
		Transport:       transport,
		SignCount:       m.SignCount,
		DeviceName:      m.DeviceName,
		CreatedAt:       m.CreatedAt,
		LastUsedAt:      m.LastUsedAt,
	}
}