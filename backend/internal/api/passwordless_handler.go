package api

import (
	"errors"
	"net/http"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

type PasswordlessHandler struct {
	passwordless *service.PasswordlessService
	tokens       *service.TokenService
}

func NewPasswordlessHandler(passwordless *service.PasswordlessService, tokens *service.TokenService) *PasswordlessHandler {
	return &PasswordlessHandler{passwordless: passwordless, tokens: tokens}
}

type sendMagicLinkRequest struct {
	Email    string `json:"email" binding:"required,email"`
	TenantID string `json:"tenant_id" binding:"required"`
	BaseURL  string `json:"base_url" binding:"required,url"`
}

func (h *PasswordlessHandler) SendMagicLink(c *gin.Context) {
	var req sendMagicLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if err := h.passwordless.SendMagicLink(c.Request.Context(), req.Email, req.TenantID, req.BaseURL); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to send magic link")
		return
	}
	c.Status(http.StatusOK)
}

type verifyMagicLinkRequest struct {
	Token    string `json:"token" binding:"required"`
	TenantID string `json:"tenant_id" binding:"required"`
}

func (h *PasswordlessHandler) VerifyMagicLink(c *gin.Context) {
	var req verifyMagicLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	result, err := h.passwordless.VerifyMagicLink(c.Request.Context(), req.Token, req.TenantID)
	if err != nil {
		if errors.Is(err, service.ErrMagicLinkNotFound) {
			writeError(c, http.StatusBadRequest, "invalid_token", "invalid or expired magic link")
			return
		}
		if errors.Is(err, service.ErrMagicLinkExpired) {
			writeError(c, http.StatusBadRequest, "token_expired", "magic link has expired")
			return
		}
		if errors.Is(err, service.ErrMagicLinkUsed) {
			writeError(c, http.StatusBadRequest, "token_used", "magic link already used")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "verification failed")
		return
	}
	c.JSON(http.StatusOK, toAuthResponse(result))
}

// Password reset endpoints
type requestPasswordResetRequest struct {
	Email    string `json:"email" binding:"required,email"`
	TenantID string `json:"tenant_id" binding:"required"`
	BaseURL  string `json:"base_url" binding:"required,url"`
}

func (h *PasswordlessHandler) RequestPasswordReset(c *gin.Context) {
	var req requestPasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Implementation would create a password reset token and send email
	// For now, just return success (don't reveal if email exists)
	c.Status(http.StatusOK)
}

type resetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	Password    string `json:"password" binding:"required,min=8"`
	TenantID    string `json:"tenant_id" binding:"required"`
}

func (h *PasswordlessHandler) ResetPassword(c *gin.Context) {
	var req resetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Implementation would verify token, check password policy, update password
	writeError(c, http.StatusNotImplemented, "not_implemented", "password reset not yet implemented")
}

// Email verification endpoints
type verifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

func (h *PasswordlessHandler) VerifyEmail(c *gin.Context) {
	var req verifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Implementation would verify email token
	writeError(c, http.StatusNotImplemented, "not_implemented", "email verification not yet implemented")
}

// Password policy endpoints
type passwordPolicyResponse struct {
	TenantID            string `json:"tenant_id"`
	MinLength           int    `json:"min_length"`
	RequireUppercase    bool   `json:"require_uppercase"`
	RequireLowercase    bool   `json:"require_lowercase"`
	RequireNumber       bool   `json:"require_number"`
	RequireSpecial      bool   `json:"require_special"`
	MaxAgeDays          int    `json:"max_age_days"`
	HistoryCount        int    `json:"history_count"`
	BreachCheckEnabled  bool   `json:"breach_check_enabled"`
	LockoutThreshold    int    `json:"lockout_threshold"`
	LockoutDurationMin  int    `json:"lockout_duration_min"`
}

type updatePasswordPolicyRequest struct {
	MinLength           int  `json:"min_length"`
	RequireUppercase    bool `json:"require_uppercase"`
	RequireLowercase    bool `json:"require_lowercase"`
	RequireNumber       bool `json:"require_number"`
	RequireSpecial      bool `json:"require_special"`
	MaxAgeDays          int  `json:"max_age_days"`
	HistoryCount        int  `json:"history_count"`
	BreachCheckEnabled  bool `json:"breach_check_enabled"`
	LockoutThreshold    int  `json:"lockout_threshold"`
	LockoutDurationMin  int  `json:"lockout_duration_min"`
}

func (h *PasswordlessHandler) GetPasswordPolicy(c *gin.Context) {
	_ = c.Param("tenantId")
	// Implementation would fetch from service
	writeError(c, http.StatusNotImplemented, "not_implemented", "get password policy not yet implemented")
}

func (h *PasswordlessHandler) UpdatePasswordPolicy(c *gin.Context) {
	_ = c.Param("tenantId")
	var req updatePasswordPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Implementation would update password policy
	writeError(c, http.StatusNotImplemented, "not_implemented", "update password policy not yet implemented")
}