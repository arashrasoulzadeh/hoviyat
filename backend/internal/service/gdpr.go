package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

var (
	ErrExportNotFound    = errors.New("export not found")
	ErrExportExpired     = errors.New("export expired")
	ErrErasureNotFound   = errors.New("erasure request not found")
	ErrErasureInProgress = errors.New("erasure already in progress")
)

type GDPRService struct {
	users           domain.UserRepository
	memberships     domain.MembershipRepository
	teamMemberships domain.TeamMembershipRepository
	auditLogs       domain.AuditLogRepository
	exportRepo      domain.AuditExportRepository
}

func NewGDPRService(
	users domain.UserRepository,
	memberships domain.MembershipRepository,
	teamMemberships domain.TeamMembershipRepository,
	auditLogs domain.AuditLogRepository,
	exportRepo domain.AuditExportRepository,
) *GDPRService {
	return &GDPRService{
		users:           users,
		memberships:     memberships,
		teamMemberships: teamMemberships,
		auditLogs:       auditLogs,
		exportRepo:      exportRepo,
	}
}

type ExportRequest struct {
	UserID   string
	TenantID string
	Email    string
}

type ExportResult struct {
	RequestID string
	UserData  map[string]any
	ExpiresAt time.Time
}

func (s *GDPRService) RequestExport(ctx context.Context, req ExportRequest) (*ExportResult, error) {
	user, err := s.users.FindByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	if req.TenantID != "" {
		_, err := s.memberships.FindByUserAndTenant(ctx, user.ID, req.TenantID)
		if err != nil {
			return nil, fmt.Errorf("user not a member of tenant")
		}
	}

	memberships, err := s.memberships.ListByUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	teamMemberships, err := s.teamMemberships.ListByUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	auditLogs, err := s.auditLogs.List(ctx, domain.AuditLogFilter{
		ActorID: user.ID,
		Limit:   1000,
	})
	if err != nil {
		return nil, err
	}

	data := map[string]any{
		"user": map[string]any{
			"id":        user.ID,
			"email":     user.Email,
			"created_at": user.CreatedAt,
			"updated_at": user.UpdatedAt,
		},
		"memberships":       memberships,
		"team_memberships":  teamMemberships,
		"audit_logs":        auditLogs,
		"exported_at":       time.Now(),
		"exported_by_email": req.Email,
	}

	requestID := fmt.Sprintf("export_%s_%d", user.ID, time.Now().UnixNano())
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days

	export := &domain.AuditExport{
		RequestID: requestID,
		UserID:    user.ID,
		TenantID:  req.TenantID,
		Email:     req.Email,
		Data:      data,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		Status:    "ready",
	}

	if err := s.exportRepo.Create(ctx, export); err != nil {
		return nil, err
	}

	// Log the export event
	_ = s.auditLogs.Create(context.Background(), &domain.AuditLog{
		TenantID:  req.TenantID,
		EventType: domain.AuditEventTypeDataExported,
		ActorID:   user.ID,
		ActorType: "user",
		Action:    "Data export requested",
		After: map[string]any{
			"export_request_id": requestID,
			"expires_at":        expiresAt,
		},
	})

	return &ExportResult{
		RequestID: requestID,
		UserData:  data,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *GDPRService) GetExport(ctx context.Context, requestID string) (*domain.AuditExport, error) {
	export, err := s.exportRepo.FindByID(ctx, requestID)
	if err != nil {
		if errors.Is(err, domain.ErrAuditExportNotFound) {
			return nil, ErrExportNotFound
		}
		return nil, err
	}

	if export.ExpiresAt.Before(time.Now()) {
		export.Status = "expired"
		s.exportRepo.Update(ctx, export)
		return nil, ErrExportExpired
	}

	return export, nil
}

type ErasureRequest struct {
	UserID   string
	TenantID string
	Email    string
	Reason   string
}

type ErasureResult struct {
	RequestID string
	Status    string
}

func (s *GDPRService) RequestErasure(ctx context.Context, req ErasureRequest) (*ErasureResult, error) {
	user, err := s.users.FindByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	if req.TenantID != "" {
		_, err := s.memberships.FindByUserAndTenant(ctx, user.ID, req.TenantID)
		if err != nil {
			return nil, fmt.Errorf("user not a member of tenant")
		}
	}

	// Check if erasure already requested
	existing, err := s.exportRepo.FindByEmailAndStatus(ctx, req.Email, "pending_erasure")
	if err == nil && existing != nil {
		return nil, ErrErasureInProgress
	}

	requestID := fmt.Sprintf("erasure_%s_%d", user.ID, time.Now().UnixNano())

	// Log the erasure request
	_ = s.auditLogs.Create(context.Background(), &domain.AuditLog{
		TenantID:  req.TenantID,
		EventType: domain.AuditEventTypeDataErased,
		ActorID:   user.ID,
		ActorType: "user",
		Action:    "Data erasure requested",
		After: map[string]any{
			"erasure_request_id": requestID,
			"reason":             req.Reason,
		},
	})

	if err := s.exportRepo.Create(ctx, &domain.AuditExport{
		RequestID: requestID,
		UserID:    user.ID,
		TenantID:  req.TenantID,
		Email:     req.Email,
		Data: map[string]any{
			"reason":       req.Reason,
			"requested_at": time.Now(),
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		Status:    "pending_erasure",
	}); err != nil {
		return nil, err
	}

	return &ErasureResult{
		RequestID: requestID,
		Status:    "pending",
	}, nil
}

func (s *GDPRService) ExecuteErasure(ctx context.Context, requestID string) error {
	export, err := s.exportRepo.FindByID(ctx, requestID)
	if err != nil {
		return err
	}

	if export.Status != "pending_erasure" {
		return fmt.Errorf("erasure not in pending state")
	}

	// In a real implementation, this would:
	// 1. Delete user data from all tables
	// 2. Anonymize audit logs
	// 3. Remove from memberships
	// 4. etc.

	export.Status = "completed"
	export.Data["completed_at"] = time.Now()
	return s.exportRepo.Update(ctx, export)
}