package service

import (
	"context"
	"fmt"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

type AuditLogService struct {
	repo   domain.AuditLogRepository
	tenant string // default tenant for system events
}

func NewAuditLogService(repo domain.AuditLogRepository) *AuditLogService {
	return &AuditLogService{repo: repo}
}

func (s *AuditLogService) Log(ctx context.Context, log *domain.AuditLog) error {
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now()
	}
	if log.ID == "" {
		log.ID = fmt.Sprintf("audit_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond())
	}
	return s.repo.Create(ctx, log)
}

func (s *AuditLogService) LogEvent(ctx context.Context, tenantID, eventType, actorID, actorType, resourceType, resourceID, action string, before, after, metadata map[string]any) error {
	log := &domain.AuditLog{
		TenantID:     tenantID,
		EventType:    domain.AuditEventType(eventType),
		ActorID:      actorID,
		ActorType:    actorType,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Action:       action,
		Before:       before,
		After:        after,
		Metadata:     metadata,
		Timestamp:    time.Now(),
	}
	return s.repo.Create(ctx, log)
}

func (s *AuditLogService) LogUserEvent(ctx context.Context, tenantID, eventType, actorID, userID, action string, before, after map[string]any, metadata map[string]any) error {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["target_user_id"] = userID
	return s.LogEvent(ctx, tenantID, eventType, actorID, "user", "user", userID, action, before, after, metadata)
}

func (s *AuditLogService) LogAuthEvent(ctx context.Context, tenantID, eventType, actorID, action string, metadata map[string]any) error {
	return s.LogEvent(ctx, tenantID, eventType, actorID, "user", "auth", "", action, nil, nil, metadata)
}

func (s *AuditLogService) LogTokenEvent(ctx context.Context, tenantID, eventType, actorID, tokenID, action string, metadata map[string]any) error {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["token_id"] = tokenID
	return s.LogEvent(ctx, tenantID, eventType, actorID, "user", "token", tokenID, action, nil, nil, metadata)
}

func (s *AuditLogService) LogRoleEvent(ctx context.Context, tenantID, eventType, actorID, roleName, action string, metadata map[string]any) error {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["role_name"] = roleName
	return s.LogEvent(ctx, tenantID, eventType, actorID, "user", "role", roleName, action, nil, nil, metadata)
}

func (s *AuditLogService) LogPolicyEvent(ctx context.Context, tenantID, eventType, actorID, policyID, action string, before, after map[string]any, metadata map[string]any) error {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["policy_id"] = policyID
	return s.LogEvent(ctx, tenantID, eventType, actorID, "user", "policy", policyID, action, before, after, metadata)
}

func (s *AuditLogService) LogACLEvent(ctx context.Context, tenantID, eventType, actorID, subjectType, subjectID, resourceType, resourceID, permission, action string, metadata map[string]any) error {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["subject_type"] = subjectType
	metadata["subject_id"] = subjectID
	metadata["permission"] = permission
	return s.LogEvent(ctx, tenantID, eventType, actorID, "user", resourceType, resourceID, action, nil, nil, metadata)
}

func (s *AuditLogService) LogTenantEvent(ctx context.Context, tenantID, eventType, actorID, action string, before, after map[string]any, metadata map[string]any) error {
	return s.LogEvent(ctx, tenantID, eventType, actorID, "user", "tenant", tenantID, action, before, after, metadata)
}

func (s *AuditLogService) LogClientEvent(ctx context.Context, tenantID, eventType, actorID, clientID, action string, before, after map[string]any, metadata map[string]any) error {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["client_id"] = clientID
	return s.LogEvent(ctx, tenantID, eventType, actorID, "user", "client", clientID, action, before, after, metadata)
}

func (s *AuditLogService) LogConsentEvent(ctx context.Context, tenantID, eventType, actorID, clientID, action string, metadata map[string]any) error {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["client_id"] = clientID
	return s.LogEvent(ctx, tenantID, eventType, actorID, "user", "consent", clientID, action, nil, nil, metadata)
}

func (s *AuditLogService) List(ctx context.Context, filter domain.AuditLogFilter) ([]*domain.AuditLog, error) {
	return s.repo.List(ctx, filter)
}

func (s *AuditLogService) Count(ctx context.Context, filter domain.AuditLogFilter) (int64, error) {
	return s.repo.Count(ctx, filter)
}

func (s *AuditLogService) VerifyChain(ctx context.Context, tenantID string, fromTimestamp time.Time) (bool, error) {
	return s.repo.VerifyChain(ctx, tenantID, fromTimestamp)
}

func (s *AuditLogService) GetByID(ctx context.Context, id string) (*domain.AuditLog, error) {
	return s.repo.FindByID(ctx, id)
}

// Helper to create audit log from HTTP request context
func (s *AuditLogService) LogFromContext(ctx context.Context, tenantID, eventType, action string, before, after map[string]any, metadata map[string]any) error {
	actorID, _ := ctx.Value("user_id").(string)
	if actorID == "" {
		actorID = "system"
	}
	actorType := "user"
	if actorID == "system" {
		actorType = "system"
	}

	if metadata == nil {
		metadata = make(map[string]any)
	}
	if ip, ok := ctx.Value("client_ip").(string); ok {
		metadata["client_ip"] = ip
	}
	if ua, ok := ctx.Value("user_agent").(string); ok {
		metadata["user_agent"] = ua
	}

	return s.LogEvent(ctx, tenantID, eventType, actorID, actorType, "", "", action, before, after, metadata)
}