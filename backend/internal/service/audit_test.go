package service

import (
	"context"
	"testing"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAuditLogRepository struct {
	logs    map[string]*domain.AuditLog
	counter int
}

func newFakeAuditLogRepository() *fakeAuditLogRepository {
	return &fakeAuditLogRepository{
		logs:    make(map[string]*domain.AuditLog),
		counter: 0,
	}
}

func (f *fakeAuditLogRepository) Create(_ context.Context, log *domain.AuditLog) error {
	if log.ID == "" {
		f.counter++
		log.ID = log.TenantID + "-audit-" + time.Now().Format("150405.000000000") + string(rune('A'+f.counter))
	}
	log.Hash = "fake-hash-" + log.ID
	f.logs[log.ID] = log
	return nil
}

func (f *fakeAuditLogRepository) FindByID(_ context.Context, id string) (*domain.AuditLog, error) {
	log, ok := f.logs[id]
	if !ok {
		return nil, domain.ErrAuditLogNotFound
	}
	return log, nil
}

func (f *fakeAuditLogRepository) List(_ context.Context, filter domain.AuditLogFilter) ([]*domain.AuditLog, error) {
	var out []*domain.AuditLog
	for _, log := range f.logs {
		if filter.TenantID != "" && log.TenantID != filter.TenantID {
			continue
		}
		if len(filter.EventTypes) > 0 {
			found := false
			for _, et := range filter.EventTypes {
				if log.EventType == et {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		out = append(out, log)
	}
	return out, nil
}

func (f *fakeAuditLogRepository) Count(_ context.Context, filter domain.AuditLogFilter) (int64, error) {
	logs, _ := f.List(context.Background(), filter)
	return int64(len(logs)), nil
}

func (f *fakeAuditLogRepository) VerifyChain(_ context.Context, tenantID string, fromTimestamp time.Time) (bool, error) {
	return true, nil
}

func TestAuditLogService_LogEvent(t *testing.T) {
	repo := newFakeAuditLogRepository()
	service := NewAuditLogService(repo)

	err := service.LogEvent(context.Background(), "tenant-1", "user.created", "user-1", "user", "user", "user-1", "User created", nil, map[string]any{"email": "test@example.com"}, map[string]any{"ip": "192.168.1.1"})
	assert.NoError(t, err)

	logs, err := service.List(context.Background(), domain.AuditLogFilter{TenantID: "tenant-1"})
	assert.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, domain.AuditEventTypeUserCreated, logs[0].EventType)
	assert.Equal(t, "user-1", logs[0].ActorID)
}

func TestAuditLogService_LogUserEvent(t *testing.T) {
	repo := newFakeAuditLogRepository()
	service := NewAuditLogService(repo)

	err := service.LogUserEvent(context.Background(), "tenant-1", "user.login", "user-1", "user-2", "User logged in", nil, map[string]any{"mfa": true}, map[string]any{"ip": "192.168.1.1"})
	assert.NoError(t, err)

	logs, err := service.List(context.Background(), domain.AuditLogFilter{TenantID: "tenant-1"})
	assert.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, domain.AuditEventTypeUserLogin, logs[0].EventType)
}

func TestAuditLogService_LogAuthEvent(t *testing.T) {
	repo := newFakeAuditLogRepository()
	service := NewAuditLogService(repo)

	err := service.LogAuthEvent(context.Background(), "tenant-1", "user.login", "user-1", "User logged in successfully", map[string]any{"mfa_verified": true})
	assert.NoError(t, err)

	logs, err := service.List(context.Background(), domain.AuditLogFilter{TenantID: "tenant-1"})
	assert.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, domain.AuditEventTypeUserLogin, logs[0].EventType)
}

func TestAuditLogService_List(t *testing.T) {
	repo := newFakeAuditLogRepository()
	service := NewAuditLogService(repo)

	// Create multiple events
	service.LogEvent(context.Background(), "tenant-1", "user.created", "user-1", "user", "user", "user-1", "Created", nil, nil, nil)
	service.LogEvent(context.Background(), "tenant-1", "user.login", "user-1", "user", "user", "user-1", "Logged in", nil, nil, nil)
	service.LogEvent(context.Background(), "tenant-2", "user.created", "user-2", "user", "user", "user-2", "Created", nil, nil, nil)

	// Filter by tenant
	logs, err := service.List(context.Background(), domain.AuditLogFilter{TenantID: "tenant-1"})
	assert.NoError(t, err)
	assert.Len(t, logs, 2)

	// Filter by event type
	logs, err = service.List(context.Background(), domain.AuditLogFilter{TenantID: "tenant-1", EventTypes: []domain.AuditEventType{domain.AuditEventTypeUserLogin}})
	assert.NoError(t, err)
	assert.Len(t, logs, 1)
	assert.Equal(t, domain.AuditEventTypeUserLogin, logs[0].EventType)
}

func TestAuditLogService_Count(t *testing.T) {
	repo := newFakeAuditLogRepository()
	service := NewAuditLogService(repo)

	service.LogEvent(context.Background(), "tenant-1", "user.created", "user-1", "user", "user", "user-1", "Created", nil, nil, nil)

	count, err := service.Count(context.Background(), domain.AuditLogFilter{TenantID: "tenant-1"})
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestAuditLogService_VerifyChain(t *testing.T) {
	repo := newFakeAuditLogRepository()
	service := NewAuditLogService(repo)

	valid, err := service.VerifyChain(context.Background(), "tenant-1", time.Now().Add(-time.Hour))
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestAuditLogService_GetByID(t *testing.T) {
	repo := newFakeAuditLogRepository()
	service := NewAuditLogService(repo)

	service.LogEvent(context.Background(), "tenant-1", "user.created", "user-1", "user", "user", "user-1", "Created", nil, nil, nil)

	logs, _ := service.List(context.Background(), domain.AuditLogFilter{TenantID: "tenant-1"})
	require.Len(t, logs, 1)

	found, err := service.GetByID(context.Background(), logs[0].ID)
	assert.NoError(t, err)
	assert.Equal(t, logs[0].ID, found.ID)
}

func TestAuditLogService_GetByID_NotFound(t *testing.T) {
	repo := newFakeAuditLogRepository()
	service := NewAuditLogService(repo)

	_, err := service.GetByID(context.Background(), "non-existent")
	assert.ErrorIs(t, err, domain.ErrAuditLogNotFound)
}