package domain

import (
	"context"
	"errors"
	"time"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	AuditEventTypeUserCreated        AuditEventType = "user.created"
	AuditEventTypeUserUpdated        AuditEventType = "user.updated"
	AuditEventTypeUserDeleted        AuditEventType = "user.deleted"
	AuditEventTypeUserLogin          AuditEventType = "user.login"
	AuditEventTypeUserLogout         AuditEventType = "user.logout"
	AuditEventTypeUserLoginFailed    AuditEventType = "user.login_failed"
	AuditEventTypeTokenIssued        AuditEventType = "token.issued"
	AuditEventTypeTokenRevoked       AuditEventType = "token.revoked"
	AuditEventTypeTokenRefreshed     AuditEventType = "token.refreshed"
	AuditEventTypeRoleAssigned       AuditEventType = "role.assigned"
	AuditEventTypeRoleRevoked        AuditEventType = "role.revoked"
	AuditEventTypePermissionGranted  AuditEventType = "permission.granted"
	AuditEventTypePermissionRevoked  AuditEventType = "permission.revoked"
	AuditEventTypePolicyCreated      AuditEventType = "policy.created"
	AuditEventTypePolicyUpdated      AuditEventType = "policy.updated"
	AuditEventTypePolicyDeleted      AuditEventType = "policy.deleted"
	AuditEventTypePolicyActivated    AuditEventType = "policy.activated"
	AuditEventTypeACLGranted         AuditEventType = "acl.granted"
	AuditEventTypeACLRevoked         AuditEventType = "acl.revoked"
	AuditEventTypeTenantCreated      AuditEventType = "tenant.created"
	AuditEventTypeTenantUpdated      AuditEventType = "tenant.updated"
	AuditEventTypeTenantDeleted      AuditEventType = "tenant.deleted"
	AuditEventTypeTeamCreated        AuditEventType = "team.created"
	AuditEventTypeTeamUpdated        AuditEventType = "team.updated"
	AuditEventTypeTeamDeleted        AuditEventType = "team.deleted"
	AuditEventTypeMemberAdded        AuditEventType = "member.added"
	AuditEventTypeMemberRemoved      AuditEventType = "member.removed"
	AuditEventTypeClientRegistered   AuditEventType = "client.registered"
	AuditEventTypeClientUpdated      AuditEventType = "client.updated"
	AuditEventTypeClientDeleted      AuditEventType = "client.deleted"
	AuditEventTypeConsentGranted     AuditEventType = "consent.granted"
	AuditEventTypeConsentRevoked     AuditEventType = "consent.revoked"
	AuditEventTypeDataExported       AuditEventType = "data.exported"
	AuditEventTypeDataErased         AuditEventType = "data.erased"
	AuditEventTypeMFAEnrolled        AuditEventType = "mfa.enrolled"
	AuditEventTypeMFARevoked         AuditEventType = "mfa.revoked"
	AuditEventTypePasswordChanged    AuditEventType = "password.changed"
	AuditEventTypePasswordReset      AuditEventType = "password.reset"
	AuditEventTypeEmailVerified      AuditEventType = "email.verified"
	AuditEventTypeImpersonationStart AuditEventType = "impersonation.start"
	AuditEventTypeImpersonationEnd   AuditEventType = "impersonation.end"
)

// AuditLog represents an immutable audit log entry
type AuditLog struct {
	ID           string
	TenantID     string
	EventType    AuditEventType
	ActorID      string // User or system that performed the action
	ActorType    string // "user", "system", "client", "impersonator"
	ResourceType string // Type of resource affected (user, role, policy, etc.)
	ResourceID   string // ID of the resource affected
	Action       string // Human-readable action description
	Before       map[string]any // State before the change (JSON)
	After        map[string]any // State after the change (JSON)
	Metadata     map[string]any // Additional context (IP, user-agent, etc.)
	Timestamp    time.Time
	Hash         string // Cryptographic hash for tamper-evidence
	PrevHash     string // Hash of previous log entry (chain)
}

var (
	ErrAuditLogNotFound    = errors.New("audit log not found")
	ErrAuditExportNotFound = errors.New("audit export not found")
	ErrWebhookNotFound     = errors.New("webhook not found")
	ErrWebhookDeliveryFail = errors.New("webhook delivery failed")
)

// AuditLogRepository defines the interface for audit log persistence
type AuditLogRepository interface {
	Create(ctx context.Context, log *AuditLog) error
	FindByID(ctx context.Context, id string) (*AuditLog, error)
	List(ctx context.Context, filter AuditLogFilter) ([]*AuditLog, error)
	Count(ctx context.Context, filter AuditLogFilter) (int64, error)
	// VerifyChain verifies the integrity of the audit log chain
	VerifyChain(ctx context.Context, tenantID string, fromTimestamp time.Time) (bool, error)
}

// AuditLogFilter defines filtering options for audit log queries
type AuditLogFilter struct {
	TenantID     string
	EventTypes   []AuditEventType
	ActorID      string
	ResourceType string
	ResourceID   string
	StartTime    time.Time
	EndTime      time.Time
	Limit        int
	Offset       int
	SortOrder    string // "asc" or "desc"
}

// AuditExport represents a GDPR data export
type AuditExport struct {
	RequestID string
	UserID    string
	TenantID  string
	Email     string
	Data      map[string]any
	CreatedAt time.Time
	ExpiresAt time.Time
	Status    string // "pending", "ready", "expired", "pending_erasure", "completed"
}

type AuditExportRepository interface {
	Create(ctx context.Context, export *AuditExport) error
	FindByID(ctx context.Context, requestID string) (*AuditExport, error)
	FindByEmailAndStatus(ctx context.Context, email, status string) (*AuditExport, error)
	Update(ctx context.Context, export *AuditExport) error
	DeleteExpired(ctx context.Context) error
}