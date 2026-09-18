package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type magicLinkRepository struct {
	db *gorm.DB
}

func NewMagicLinkRepository(db *gorm.DB) domain.MagicLinkRepository {
	return &magicLinkRepository{db: db}
}

func (r *magicLinkRepository) Create(ctx context.Context, m *domain.MagicLink) error {
	tokenHash := hashToken(m.Token)
	model := &magicLinkModel{
		ID:        m.ID,
		UserID:    m.UserID,
		TenantID:  m.TenantID,
		TokenHash: tokenHash,
		ExpiresAt: m.ExpiresAt,
	}
	if err := r.db.WithContext(ctx).Create(model).Error; err != nil {
		return err
	}
	m.ID = model.ID
	m.CreatedAt = model.CreatedAt
	return nil
}

func (r *magicLinkRepository) FindByToken(ctx context.Context, token string) (*domain.MagicLink, error) {
	tokenHash := hashToken(token)
	var m magicLinkModel
	if err := r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrMagicLinkNotFound
		}
		return nil, err
	}
	if m.UsedAt != nil {
		return nil, domain.ErrMagicLinkUsed
	}
	if time.Now().After(m.ExpiresAt) {
		return nil, domain.ErrMagicLinkExpired
	}
	return fromMagicLinkModel(&m), nil
}

func (r *magicLinkRepository) MarkUsed(ctx context.Context, id string) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&magicLinkModel{}).Where("id = ?", id).Update("used_at", now).Error
}

func (r *magicLinkRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&magicLinkModel{}).Error
}

func fromMagicLinkModel(m *magicLinkModel) *domain.MagicLink {
	return &domain.MagicLink{
		ID:        m.ID,
		UserID:    m.UserID,
		TenantID:  m.TenantID,
		Token:     "", // never return raw token
		ExpiresAt: m.ExpiresAt,
		UsedAt:    m.UsedAt,
		CreatedAt: m.CreatedAt,
	}
}

type passwordPolicyRepository struct {
	db *gorm.DB
}

func NewPasswordPolicyRepository(db *gorm.DB) domain.PasswordPolicyRepository {
	return &passwordPolicyRepository{db: db}
}

func (r *passwordPolicyRepository) Get(ctx context.Context, tenantID string) (*domain.PasswordPolicy, error) {
	var m passwordPolicyModel
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Return default policy
			return &domain.PasswordPolicy{
				TenantID:            tenantID,
				MinLength:           8,
				RequireUppercase:    false,
				RequireLowercase:    false,
				RequireNumber:       false,
				RequireSpecial:      false,
				MaxAgeDays:          0,
				HistoryCount:        5,
				BreachCheckEnabled:  true,
				LockoutThreshold:    5,
				LockoutDurationMin:  15,
			}, nil
		}
		return nil, err
	}
	return fromPasswordPolicyModel(&m), nil
}

func (r *passwordPolicyRepository) Update(ctx context.Context, p *domain.PasswordPolicy) error {
	model := &passwordPolicyModel{
		TenantID:            p.TenantID,
		MinLength:           p.MinLength,
		RequireUppercase:    p.RequireUppercase,
		RequireLowercase:    p.RequireLowercase,
		RequireNumber:       p.RequireNumber,
		RequireSpecial:      p.RequireSpecial,
		MaxAgeDays:          p.MaxAgeDays,
		HistoryCount:        p.HistoryCount,
		BreachCheckEnabled:  p.BreachCheckEnabled,
		LockoutThreshold:    p.LockoutThreshold,
		LockoutDurationMin:  p.LockoutDurationMin,
	}
	// Upsert
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"min_length", "require_uppercase", "require_lowercase", "require_number", "require_special", "max_age_days", "history_count", "breach_check_enabled", "lockout_threshold", "lockout_duration_min", "updated_at"}),
	}).Create(model).Error
}

func fromPasswordPolicyModel(m *passwordPolicyModel) *domain.PasswordPolicy {
	return &domain.PasswordPolicy{
		TenantID:            m.TenantID,
		MinLength:           m.MinLength,
		RequireUppercase:    m.RequireUppercase,
		RequireLowercase:    m.RequireLowercase,
		RequireNumber:       m.RequireNumber,
		RequireSpecial:      m.RequireSpecial,
		MaxAgeDays:          m.MaxAgeDays,
		HistoryCount:        m.HistoryCount,
		BreachCheckEnabled:  m.BreachCheckEnabled,
		LockoutThreshold:    m.LockoutThreshold,
		LockoutDurationMin:  m.LockoutDurationMin,
		CreatedAt:           m.CreatedAt,
		UpdatedAt:           m.UpdatedAt,
	}
}

type failedLoginAttemptRepository struct {
	db *gorm.DB
}

func NewFailedLoginAttemptRepository(db *gorm.DB) domain.FailedLoginAttemptRepository {
	return &failedLoginAttemptRepository{db: db}
}

func (r *failedLoginAttemptRepository) Increment(ctx context.Context, email, tenantID, ip string) (*domain.FailedLoginAttempt, error) {
	var m failedLoginAttemptModel
	err := r.db.WithContext(ctx).Where("email = ? AND tenant_id = ? AND ip = ?", email, tenantID, ip).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			m = failedLoginAttemptModel{
				Email:    email,
				TenantID: tenantID,
				IP:       ip,
				Count:    1,
			}
			if err := r.db.WithContext(ctx).Create(&m).Error; err != nil {
				return nil, err
			}
			return fromFailedLoginAttemptModel(&m), nil
		}
		return nil, err
	}
	m.Count++
	if m.LockedUntil != nil && time.Now().After(*m.LockedUntil) {
		m.LockedUntil = nil
	}
	if err := r.db.WithContext(ctx).Save(&m).Error; err != nil {
		return nil, err
	}
	return fromFailedLoginAttemptModel(&m), nil
}

func (r *failedLoginAttemptRepository) Reset(ctx context.Context, email, tenantID, ip string) error {
	return r.db.WithContext(ctx).Where("email = ? AND tenant_id = ? AND ip = ?", email, tenantID, ip).Delete(&failedLoginAttemptModel{}).Error
}

func (r *failedLoginAttemptRepository) Find(ctx context.Context, email, tenantID, ip string) (*domain.FailedLoginAttempt, error) {
	var m failedLoginAttemptModel
	if err := r.db.WithContext(ctx).Where("email = ? AND tenant_id = ? AND ip = ?", email, tenantID, ip).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return fromFailedLoginAttemptModel(&m), nil
}

func fromFailedLoginAttemptModel(m *failedLoginAttemptModel) *domain.FailedLoginAttempt {
	return &domain.FailedLoginAttempt{
		ID:           m.ID,
		Email:        m.Email,
		TenantID:     m.TenantID,
		IP:           m.IP,
		Count:        m.Count,
		LockedUntil:  m.LockedUntil,
		CreatedAt:    m.CreatedAt,
		UpdatedAt:    m.UpdatedAt,
	}
}

type passwordResetTokenRepository struct {
	db *gorm.DB
}

func NewPasswordResetTokenRepository(db *gorm.DB) domain.PasswordResetTokenRepository {
	return &passwordResetTokenRepository{db: db}
}

func (r *passwordResetTokenRepository) Create(ctx context.Context, t *domain.PasswordResetToken) error {
	tokenHash := hashToken(t.Token)
	model := &passwordResetTokenModel{
		ID:        t.ID,
		UserID:    t.UserID,
		TenantID:  t.TenantID,
		TokenHash: tokenHash,
		ExpiresAt: t.ExpiresAt,
	}
	if err := r.db.WithContext(ctx).Create(model).Error; err != nil {
		return err
	}
	t.ID = model.ID
	t.CreatedAt = model.CreatedAt
	return nil
}

func (r *passwordResetTokenRepository) FindByToken(ctx context.Context, token string) (*domain.PasswordResetToken, error) {
	tokenHash := hashToken(token)
	var m passwordResetTokenModel
	if err := r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrPasswordResetTokenNotFound
		}
		return nil, err
	}
	if m.UsedAt != nil {
		return nil, domain.ErrPasswordResetTokenUsed
	}
	if time.Now().After(m.ExpiresAt) {
		return nil, domain.ErrPasswordResetTokenExpired
	}
	return fromPasswordResetTokenModel(&m), nil
}

func (r *passwordResetTokenRepository) MarkUsed(ctx context.Context, id string) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&passwordResetTokenModel{}).Where("id = ?", id).Update("used_at", now).Error
}

func (r *passwordResetTokenRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&passwordResetTokenModel{}).Error
}

func fromPasswordResetTokenModel(m *passwordResetTokenModel) *domain.PasswordResetToken {
	return &domain.PasswordResetToken{
		ID:        m.ID,
		UserID:    m.UserID,
		TenantID:  m.TenantID,
		Token:     "",
		ExpiresAt: m.ExpiresAt,
		UsedAt:    m.UsedAt,
		CreatedAt: m.CreatedAt,
	}
}

type emailVerificationTokenRepository struct {
	db *gorm.DB
}

func NewEmailVerificationTokenRepository(db *gorm.DB) domain.EmailVerificationTokenRepository {
	return &emailVerificationTokenRepository{db: db}
}

func (r *emailVerificationTokenRepository) Create(ctx context.Context, t *domain.EmailVerificationToken) error {
	tokenHash := hashToken(t.Token)
	model := &emailVerificationTokenModel{
		ID:        t.ID,
		UserID:    t.UserID,
		TenantID:  t.TenantID,
		Email:     t.Email,
		TokenHash: tokenHash,
		ExpiresAt: t.ExpiresAt,
	}
	if err := r.db.WithContext(ctx).Create(model).Error; err != nil {
		return err
	}
	t.ID = model.ID
	t.CreatedAt = model.CreatedAt
	return nil
}

func (r *emailVerificationTokenRepository) FindByToken(ctx context.Context, token string) (*domain.EmailVerificationToken, error) {
	tokenHash := hashToken(token)
	var m emailVerificationTokenModel
	if err := r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrEmailVerificationTokenNotFound
		}
		return nil, err
	}
	if time.Now().After(m.ExpiresAt) {
		return nil, domain.ErrEmailVerificationTokenExpired
	}
	return fromEmailVerificationTokenModel(&m), nil
}

func (r *emailVerificationTokenRepository) MarkVerified(ctx context.Context, id string) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&emailVerificationTokenModel{}).Where("id = ?", id).Update("verified_at", now).Error
}

func (r *emailVerificationTokenRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&emailVerificationTokenModel{}).Error
}

func fromEmailVerificationTokenModel(m *emailVerificationTokenModel) *domain.EmailVerificationToken {
	return &domain.EmailVerificationToken{
		ID:          m.ID,
		UserID:      m.UserID,
		TenantID:    m.TenantID,
		Email:       m.Email,
		Token:       "",
		ExpiresAt:   m.ExpiresAt,
		VerifiedAt:  m.VerifiedAt,
		CreatedAt:   m.CreatedAt,
	}
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}