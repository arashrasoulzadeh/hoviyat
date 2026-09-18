package api

import (
	"errors"
	"net/http"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/middleware"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

type MFAHandler struct {
	mfa    *service.MFAService
	tokens *service.TokenService
}

func NewMFAHandler(mfa *service.MFAService, tokens *service.TokenService) *MFAHandler {
	return &MFAHandler{mfa: mfa, tokens: tokens}
}

type enrollTOTPRequest struct {
	Name string `json:"name" binding:"required"`
}

type enrollTOTPResponse struct {
	MethodID    string   `json:"method_id"`
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
}

func (h *MFAHandler) EnrollTOTP(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	id, _ := userID.(string)
	tenantID, _ := c.Get(middleware.ContextTenantID)
	tid, _ := tenantID.(string)

	var req enrollTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	method, secret, qrCode, backupCodes, err := h.mfa.EnrollTOTP(c.Request.Context(), id, tid, req.Name)
	if err != nil {
		if errors.Is(err, service.ErrMFAAlreadyEnrolled) {
			writeError(c, http.StatusConflict, "already_enrolled", "totp already enrolled")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to enroll totp")
		return
	}

	c.JSON(http.StatusCreated, enrollTOTPResponse{
		MethodID:    method.ID,
		Secret:      secret,
		QRCodeURL:   qrCode,
		BackupCodes: backupCodes,
	})
}

type verifyTOTPRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

func (h *MFAHandler) VerifyTOTP(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	id, _ := userID.(string)

	var req verifyTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if err := h.mfa.VerifyTOTP(c.Request.Context(), id, req.Code); err != nil {
		if errors.Is(err, service.ErrInvalidTOTPCode) {
			writeError(c, http.StatusBadRequest, "invalid_code", "invalid totp code")
			return
		}
		if errors.Is(err, service.ErrMFAMethodNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "no mfa method found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "verification failed")
		return
	}
	c.Status(http.StatusOK)
}

type verifyBackupCodeRequest struct {
	Code string `json:"code" binding:"required"`
}

func (h *MFAHandler) VerifyBackupCode(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	id, _ := userID.(string)

	var req verifyBackupCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if err := h.mfa.VerifyBackupCode(c.Request.Context(), id, req.Code); err != nil {
		if errors.Is(err, service.ErrInvalidTOTPCode) {
			writeError(c, http.StatusBadRequest, "invalid_code", "invalid backup code")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "verification failed")
		return
	}
	c.Status(http.StatusOK)
}

type mfaMethodResponse struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Name       string    `json:"name"`
	IsPrimary  bool      `json:"is_primary"`
	VerifiedAt *string   `json:"verified_at"`
	LastUsedAt *string   `json:"last_used_at"`
	CreatedAt  string    `json:"created_at"`
}

func toMFAMethodResponse(m *domain.MFAMethod) mfaMethodResponse {
	var verifiedAt, lastUsedAt *string
	if m.VerifiedAt != nil {
		s := m.VerifiedAt.Format("2006-01-02T15:04:05Z")
		verifiedAt = &s
	}
	if m.LastUsedAt != nil {
		s := m.LastUsedAt.Format("2006-01-02T15:04:05Z")
		lastUsedAt = &s
	}
	return mfaMethodResponse{
		ID:         m.ID,
		Type:       m.Type,
		Name:       m.Name,
		IsPrimary:  m.IsPrimary,
		VerifiedAt: verifiedAt,
		LastUsedAt: lastUsedAt,
		CreatedAt:  m.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

func (h *MFAHandler) ListMethods(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	id, _ := userID.(string)

	methods, err := h.mfa.ListMethods(c.Request.Context(), id)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list methods")
		return
	}
	resp := make([]mfaMethodResponse, 0, len(methods))
	for _, m := range methods {
		resp = append(resp, toMFAMethodResponse(m))
	}
	c.JSON(http.StatusOK, resp)
}

type removeMethodRequest struct {
	MethodID string `json:"method_id" binding:"required"`
}

func (h *MFAHandler) RemoveMethod(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	id, _ := userID.(string)

	var req removeMethodRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if err := h.mfa.RemoveMethod(c.Request.Context(), id, req.MethodID); err != nil {
		if errors.Is(err, service.ErrMFAMethodNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "mfa method not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to remove method")
		return
	}
	c.Status(http.StatusNoContent)
}

type setPrimaryRequest struct {
	MethodID string `json:"method_id" binding:"required"`
}

func (h *MFAHandler) SetPrimary(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	id, _ := userID.(string)

	var req setPrimaryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if err := h.mfa.SetPrimaryMethod(c.Request.Context(), id, req.MethodID); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to set primary")
		return
	}
	c.Status(http.StatusNoContent)
}

// WebAuthn endpoints
type enrollWebAuthnRequest struct {
	DeviceName string `json:"device_name" binding:"required"`
}

type enrollWebAuthnResponse struct {
	Options     interface{} `json:"options"`
	SessionData interface{} `json:"session_data"`
}

func (h *MFAHandler) BeginWebAuthnEnrollment(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	id, _ := userID.(string)
	tenantID, _ := c.Get(middleware.ContextTenantID)
	tid, _ := tenantID.(string)

	var req enrollWebAuthnRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	options, sessionData, err := h.mfa.EnrollWebAuthn(c.Request.Context(), id, tid, req.DeviceName)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to begin webauthn enrollment")
		return
	}

	// Note: In production, sessionData should be stored in Redis with TTL
	// and returned to the client for the complete step
	c.JSON(http.StatusOK, enrollWebAuthnResponse{
		Options:     options,
		SessionData: sessionData,
	})
}

type completeWebAuthnRequest struct {
	DeviceName   string      `json:"device_name" binding:"required"`
	SessionData  interface{} `json:"session_data" binding:"required"`
	Response     interface{} `json:"response" binding:"required"`
}

func (h *MFAHandler) CompleteWebAuthnEnrollment(c *gin.Context) {
	var req completeWebAuthnRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// In practice, you'd deserialize sessionData and response properly
	// This is a simplified version
	writeError(c, http.StatusNotImplemented, "not_implemented", "complete webauthn enrollment requires proper deserialization")
}

type beginWebAuthnAuthResponse struct {
	Options     interface{} `json:"options"`
	SessionData interface{} `json:"session_data"`
}

func (h *MFAHandler) BeginWebAuthnAuthentication(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	id, _ := userID.(string)

	options, sessionData, err := h.mfa.BeginWebAuthnAuthentication(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrMFAMethodNotFound) {
			writeError(c, http.StatusNotFound, "no_credentials", "no webauthn credentials found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to begin authentication")
		return
	}

	c.JSON(http.StatusOK, beginWebAuthnAuthResponse{
		Options:     options,
		SessionData: sessionData,
	})
}

type completeWebAuthnAuthRequest struct {
	SessionData interface{} `json:"session_data" binding:"required"`
	Response    interface{} `json:"response" binding:"required"`
}

func (h *MFAHandler) CompleteWebAuthnAuthentication(c *gin.Context) {
	var req completeWebAuthnAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// In practice, deserialize and validate
	writeError(c, http.StatusNotImplemented, "not_implemented", "complete webauthn auth requires proper deserialization")
}