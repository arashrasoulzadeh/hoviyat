package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type auditExportRepository struct {
	db *gorm.DB
}

func NewAuditExportRepository(db *gorm.DB) domain.AuditExportRepository {
	return &auditExportRepository{db: db}
}

func (r *auditExportRepository) Create(ctx context.Context, export *domain.AuditExport) error {
	dataJSON, _ := json.Marshal(export.Data)
	model := &auditExportModel{
		RequestID: export.RequestID,
		UserID:    export.UserID,
		TenantID:  export.TenantID,
		Email:     export.Email,
		Data:      string(dataJSON),
		Status:    export.Status,
		CreatedAt: export.CreatedAt,
		ExpiresAt: export.ExpiresAt,
	}
	if err := r.db.WithContext(ctx).Create(model).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return domain.ErrAuditExportNotFound
		}
		return err
	}
	export.RequestID = model.RequestID
	return nil
}

func (r *auditExportRepository) FindByID(ctx context.Context, requestID string) (*domain.AuditExport, error) {
	var model auditExportModel
	if err := r.db.WithContext(ctx).Where("request_id = ?", requestID).First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrAuditExportNotFound
		}
		return nil, err
	}
	return r.exportModelToDomain(&model), nil
}

func (r *auditExportRepository) FindByEmailAndStatus(ctx context.Context, email, status string) (*domain.AuditExport, error) {
	var model auditExportModel
	if err := r.db.WithContext(ctx).Where("email = ? AND status = ?", email, status).First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return r.exportModelToDomain(&model), nil
}

func (r *auditExportRepository) Update(ctx context.Context, export *domain.AuditExport) error {
	dataJSON, _ := json.Marshal(export.Data)
	model := &auditExportModel{
		RequestID: export.RequestID,
		UserID:    export.UserID,
		TenantID:  export.TenantID,
		Email:     export.Email,
		Data:      string(dataJSON),
		Status:    export.Status,
		CreatedAt: export.CreatedAt,
		ExpiresAt: export.ExpiresAt,
	}
	res := r.db.WithContext(ctx).Model(&auditExportModel{}).Where("request_id = ?", export.RequestID).Updates(model)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domain.ErrAuditExportNotFound
	}
	return nil
}

func (r *auditExportRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&auditExportModel{}).Error
}

func (r *auditExportRepository) exportModelToDomain(m *auditExportModel) *domain.AuditExport {
	var data map[string]any
	json.Unmarshal([]byte(m.Data), &data)
	return &domain.AuditExport{
		RequestID: m.RequestID,
		UserID:    m.UserID,
		TenantID:  m.TenantID,
		Email:     m.Email,
		Data:      data,
		CreatedAt: m.CreatedAt,
		ExpiresAt: m.ExpiresAt,
		Status:    m.Status,
	}
}