package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/middleware"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

type GDPRHandler struct {
	gdpr *service.GDPRService
}

func NewGDPRHandler(gdpr *service.GDPRService) *GDPRHandler {
	return &GDPRHandler{gdpr: gdpr}
}

type exportRequest struct {
	Email    string `json:"email" binding:"required,email"`
	TenantID string `json:"tenant_id"`
}

type exportResponse struct {
	RequestID string                 `json:"request_id"`
	UserData  map[string]any         `json:"user_data"`
	ExpiresAt time.Time              `json:"expires_at"`
}

type erasureRequest struct {
	Email    string `json:"email" binding:"required,email"`
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason"`
}

type erasureResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

func (h *GDPRHandler) RequestExport(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	uid := userID.(string)

	var req exportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Use the authenticated user's ID if not provided
	if req.Email == "" {
		// Get user email from ID
		// This would require a user lookup - simplified for now
	}

	result, err := h.gdpr.RequestExport(c.Request.Context(), service.ExportRequest{
		UserID:   uid,
		TenantID: req.TenantID,
		Email:    req.Email,
	})
	if err != nil {
		if errors.Is(err, service.ErrExportNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "export not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to request export")
		return
	}

	c.JSON(http.StatusOK, exportResponse{
		RequestID: result.RequestID,
		UserData:  result.UserData,
		ExpiresAt: result.ExpiresAt,
	})
}

func (h *GDPRHandler) GetExport(c *gin.Context) {
	requestID := c.Param("requestId")
	export, err := h.gdpr.GetExport(c.Request.Context(), requestID)
	if err != nil {
		if errors.Is(err, service.ErrExportNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "export not found")
			return
		}
		if errors.Is(err, service.ErrExportExpired) {
			writeError(c, http.StatusGone, "expired", "export has expired")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to get export")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"request_id": export.RequestID,
		"user_id":    export.UserID,
		"tenant_id":  export.TenantID,
		"email":      export.Email,
		"data":       export.Data,
		"status":     export.Status,
		"created_at": export.CreatedAt,
		"expires_at": export.ExpiresAt,
	})
}

func (h *GDPRHandler) RequestErasure(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	uid := userID.(string)

	var req erasureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	result, err := h.gdpr.RequestErasure(c.Request.Context(), service.ErasureRequest{
		UserID:   uid,
		TenantID: req.TenantID,
		Email:    req.Email,
		Reason:   req.Reason,
	})
	if err != nil {
		if errors.Is(err, service.ErrErasureInProgress) {
			writeError(c, http.StatusConflict, "erasure_in_progress", "erasure already in progress")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to request erasure")
		return
	}

	c.JSON(http.StatusOK, erasureResponse{
		RequestID: result.RequestID,
		Status:    result.Status,
	})
}

func (h *GDPRHandler) GetErasureStatus(c *gin.Context) {
	_ = c.Param("requestId")
	// Implementation would check erasure status
	writeError(c, http.StatusNotImplemented, "not_implemented", "erasure status check not yet implemented")
}