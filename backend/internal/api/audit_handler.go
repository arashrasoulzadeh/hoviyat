package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

type AuditHandler struct {
	audit *service.AuditLogService
}

func NewAuditHandler(audit *service.AuditLogService) *AuditHandler {
	return &AuditHandler{audit: audit}
}

type auditLogResponse struct {
	ID           string                 `json:"id"`
	TenantID     string                 `json:"tenant_id"`
	EventType    string                 `json:"event_type"`
	ActorID      string                 `json:"actor_id"`
	ActorType    string                 `json:"actor_type"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id"`
	Action       string                 `json:"action"`
	Before       map[string]any         `json:"before,omitempty"`
	After        map[string]any         `json:"after,omitempty"`
	Metadata     map[string]any         `json:"metadata,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	Hash         string                 `json:"hash"`
	PrevHash     string                 `json:"prev_hash"`
}

func toAuditLogResponse(log *domain.AuditLog) auditLogResponse {
	return auditLogResponse{
		ID:           log.ID,
		TenantID:     log.TenantID,
		EventType:    string(log.EventType),
		ActorID:      log.ActorID,
		ActorType:    log.ActorType,
		ResourceType: log.ResourceType,
		ResourceID:   log.ResourceID,
		Action:       log.Action,
		Before:       log.Before,
		After:        log.After,
		Metadata:     log.Metadata,
		Timestamp:    log.Timestamp,
		Hash:         log.Hash,
		PrevHash:     log.PrevHash,
	}
}

func (h *AuditHandler) List(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		writeError(c, http.StatusBadRequest, "invalid_request", "tenant_id query parameter is required")
		return
	}

	filter := domain.AuditLogFilter{
		TenantID: tenantID,
	}

	if eventTypes := c.QueryArray("event_type"); len(eventTypes) > 0 {
		for _, et := range eventTypes {
			filter.EventTypes = append(filter.EventTypes, domain.AuditEventType(et))
		}
	}

	if actorID := c.Query("actor_id"); actorID != "" {
		filter.ActorID = actorID
	}
	if resourceType := c.Query("resource_type"); resourceType != "" {
		filter.ResourceType = resourceType
	}
	if resourceID := c.Query("resource_id"); resourceID != "" {
		filter.ResourceID = resourceID
	}

	if startTime := c.Query("start_time"); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			filter.StartTime = t
		}
	}
	if endTime := c.Query("end_time"); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			filter.EndTime = t
		}
	}

	if limit := c.Query("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil {
			filter.Limit = l
		}
	} else {
		filter.Limit = 100
	}

	if offset := c.Query("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil {
			filter.Offset = o
		}
	}

	if sortOrder := c.Query("sort_order"); sortOrder != "" {
		filter.SortOrder = sortOrder
	} else {
		filter.SortOrder = "desc"
	}

	logs, err := h.audit.List(c.Request.Context(), filter)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list audit logs")
		return
	}

	total, err := h.audit.Count(c.Request.Context(), filter)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to count audit logs")
		return
	}

	resp := make([]auditLogResponse, len(logs))
	for i, log := range logs {
		resp[i] = toAuditLogResponse(log)
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  resp,
		"total": total,
		"limit": filter.Limit,
		"offset": filter.Offset,
	})
}

func (h *AuditHandler) Get(c *gin.Context) {
	id := c.Param("id")
	log, err := h.audit.GetByID(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrAuditLogNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "audit log not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to get audit log")
		return
	}
	c.JSON(http.StatusOK, toAuditLogResponse(log))
}

func (h *AuditHandler) VerifyChain(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		writeError(c, http.StatusBadRequest, "invalid_request", "tenant_id query parameter is required")
		return
	}

	var fromTime time.Time
	if from := c.Query("from_time"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			fromTime = t
		}
	}

	valid, err := h.audit.VerifyChain(c.Request.Context(), tenantID, fromTime)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to verify audit chain")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":     valid,
		"tenant_id": tenantID,
		"from_time": fromTime,
	})
}

func (h *AuditHandler) Export(c *gin.Context) {
	// GDPR data export endpoint
	// This would typically be async - returning a job ID
	writeError(c, http.StatusNotImplemented, "not_implemented", "async export not yet implemented")
}