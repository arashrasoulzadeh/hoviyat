package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"gorm.io/gorm"
)

type auditLogRepository struct {
	db *gorm.DB
}

func NewAuditLogRepository(db *gorm.DB) domain.AuditLogRepository {
	return &auditLogRepository{db: db}
}

func (r *auditLogRepository) Create(ctx context.Context, log *domain.AuditLog) error {
	// Calculate hash for tamper-evidence
	hashInput := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%d",
		log.TenantID,
		log.EventType,
		log.ActorID,
		log.ActorType,
		log.ResourceType,
		log.ResourceID,
		log.Action,
		marshalJSON(log.Before),
		marshalJSON(log.After),
		marshalJSON(log.Metadata),
		log.Timestamp.UnixNano(),
	)

	// Include previous hash in chain if exists
	var prevHash string
	if log.PrevHash != "" {
		hashInput = log.PrevHash + "|" + hashInput
	} else {
		// Find the last log for this tenant to chain
		var lastLog auditLogModel
		if err := r.db.WithContext(ctx).
			Where("tenant_id = ?", log.TenantID).
			Order("timestamp DESC").
			First(&lastLog).Error; err == nil {
			prevHash = lastLog.Hash
			hashInput = prevHash + "|" + hashInput
		}
	}

	hash := sha256.Sum256([]byte(hashInput))
	log.Hash = hex.EncodeToString(hash[:])
	log.PrevHash = prevHash
	log.ID = generateID()
	log.Timestamp = time.Now()

	beforeJSON, _ := json.Marshal(log.Before)
	afterJSON, _ := json.Marshal(log.After)
	metadataJSON, _ := json.Marshal(log.Metadata)

	model := &auditLogModel{
		ID:           log.ID,
		TenantID:     log.TenantID,
		EventType:    string(log.EventType),
		ActorID:      log.ActorID,
		ActorType:    log.ActorType,
		ResourceType: log.ResourceType,
		ResourceID:   log.ResourceID,
		Action:       log.Action,
		Before:       string(beforeJSON),
		After:        string(afterJSON),
		Metadata:     string(metadataJSON),
		Timestamp:    log.Timestamp,
		Hash:         log.Hash,
		PrevHash:     log.PrevHash,
	}

	return r.db.WithContext(ctx).Create(model).Error
}

func (r *auditLogRepository) FindByID(ctx context.Context, id string) (*domain.AuditLog, error) {
	var model auditLogModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrAuditLogNotFound
		}
		return nil, err
	}
	return r.modelToDomain(&model), nil
}

func (r *auditLogRepository) List(ctx context.Context, filter domain.AuditLogFilter) ([]*domain.AuditLog, error) {
	query := r.db.WithContext(ctx).Model(&auditLogModel{})

	if filter.TenantID != "" {
		query = query.Where("tenant_id = ?", filter.TenantID)
	}
	if len(filter.EventTypes) > 0 {
		eventTypeStrs := make([]string, len(filter.EventTypes))
		for i, et := range filter.EventTypes {
			eventTypeStrs[i] = string(et)
		}
		query = query.Where("event_type IN ?", eventTypeStrs)
	}
	if filter.ActorID != "" {
		query = query.Where("actor_id = ?", filter.ActorID)
	}
	if filter.ResourceType != "" {
		query = query.Where("resource_type = ?", filter.ResourceType)
	}
	if filter.ResourceID != "" {
		query = query.Where("resource_id = ?", filter.ResourceID)
	}
	if !filter.StartTime.IsZero() {
		query = query.Where("timestamp >= ?", filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		query = query.Where("timestamp <= ?", filter.EndTime)
	}

	// Default sort by timestamp desc
	sortOrder := "DESC"
	if filter.SortOrder == "asc" {
		sortOrder = "ASC"
	}
	query = query.Order("timestamp " + sortOrder)

	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}

	var models []auditLogModel
	if err := query.Find(&models).Error; err != nil {
		return nil, err
	}

	logs := make([]*domain.AuditLog, len(models))
	for i, m := range models {
		logs[i] = r.modelToDomain(&m)
	}
	return logs, nil
}

func (r *auditLogRepository) Count(ctx context.Context, filter domain.AuditLogFilter) (int64, error) {
	query := r.db.WithContext(ctx).Model(&auditLogModel{})

	if filter.TenantID != "" {
		query = query.Where("tenant_id = ?", filter.TenantID)
	}
	if len(filter.EventTypes) > 0 {
		eventTypeStrs := make([]string, len(filter.EventTypes))
		for i, et := range filter.EventTypes {
			eventTypeStrs[i] = string(et)
		}
		query = query.Where("event_type IN ?", eventTypeStrs)
	}
	if filter.ActorID != "" {
		query = query.Where("actor_id = ?", filter.ActorID)
	}
	if filter.ResourceType != "" {
		query = query.Where("resource_type = ?", filter.ResourceType)
	}
	if filter.ResourceID != "" {
		query = query.Where("resource_id = ?", filter.ResourceID)
	}
	if !filter.StartTime.IsZero() {
		query = query.Where("timestamp >= ?", filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		query = query.Where("timestamp <= ?", filter.EndTime)
	}

	var count int64
	err := query.Count(&count).Error
	return count, err
}

func (r *auditLogRepository) VerifyChain(ctx context.Context, tenantID string, fromTimestamp time.Time) (bool, error) {
	var logs []auditLogModel
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND timestamp >= ?", tenantID, fromTimestamp).
		Order("timestamp ASC").
		Find(&logs).Error
	if err != nil {
		return false, err
	}

	if len(logs) == 0 {
		return true, nil // Nothing to verify
	}

	var prevHash string
	for i, log := range logs {
		if i == 0 {
			prevHash = log.PrevHash
			continue
		}

		// Reconstruct hash input
		hashInput := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%d",
			log.TenantID,
			log.EventType,
			log.ActorID,
			log.ActorType,
			log.ResourceType,
			log.ResourceID,
			log.Action,
			log.Before,
			log.After,
			log.Metadata,
			log.Timestamp.UnixNano(),
		)

		if prevHash != "" {
			hashInput = prevHash + "|" + hashInput
		}

		expectedHash := sha256.Sum256([]byte(hashInput))
		expectedHashStr := hex.EncodeToString(expectedHash[:])

		if log.Hash != expectedHashStr {
			return false, fmt.Errorf("chain broken at log %s: expected %s, got %s", log.ID, expectedHashStr, log.Hash)
		}

		prevHash = log.Hash
	}

	return true, nil
}

func (r *auditLogRepository) modelToDomain(m *auditLogModel) *domain.AuditLog {
	var before, after, metadata map[string]any
	json.Unmarshal([]byte(m.Before), &before)
	json.Unmarshal([]byte(m.After), &after)
	json.Unmarshal([]byte(m.Metadata), &metadata)

	return &domain.AuditLog{
		ID:           m.ID,
		TenantID:     m.TenantID,
		EventType:    domain.AuditEventType(m.EventType),
		ActorID:      m.ActorID,
		ActorType:    m.ActorType,
		ResourceType: m.ResourceType,
		ResourceID:   m.ResourceID,
		Action:       m.Action,
		Before:       before,
		After:        after,
		Metadata:     metadata,
		Timestamp:    m.Timestamp,
		Hash:         m.Hash,
		PrevHash:     m.PrevHash,
	}
}

func marshalJSON(v map[string]any) string {
	if v == nil {
		return "{}"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func generateID() string {
	// Use timestamp + random for uniqueness
	return fmt.Sprintf("audit_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond())
}