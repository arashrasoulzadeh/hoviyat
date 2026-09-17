package api

import (
	"errors"
	"net/http"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/middleware"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	auth *service.AuthService
}

func NewAuthHandler(auth *service.AuthService) *AuthHandler {
	return &AuthHandler{auth: auth}
}

type credentialsRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	TenantID string `json:"tenant_id"`
}

type authResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TenantID     string `json:"tenant_id,omitempty"`
	User         struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	Roles []string `json:"roles"`
}

func toAuthResponse(result *service.AuthResult) authResponse {
	var resp authResponse
	resp.AccessToken = result.AccessToken
	resp.RefreshToken = result.RefreshToken
	resp.TenantID = result.TenantID
	resp.Roles = result.Roles
	resp.User.ID = result.User.ID
	resp.User.Email = result.User.Email
	return resp
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req credentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := h.auth.Register(c.Request.Context(), req.Email, req.Password, req.TenantID)
	if err != nil {
		if errors.Is(err, domain.ErrUserAlreadyExists) {
			writeError(c, http.StatusConflict, "user_exists", "a user with this email already exists")
			return
		}
		if errors.Is(err, domain.ErrTenantNotFound) {
			writeError(c, http.StatusBadRequest, "tenant_not_found", "the specified tenant does not exist")
			return
		}
		if errors.Is(err, domain.ErrTenantSuspended) {
			writeError(c, http.StatusForbidden, "tenant_suspended", "the specified tenant is suspended")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to register user")
		return
	}
	c.JSON(http.StatusCreated, toAuthResponse(result))
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req credentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := h.auth.Login(c.Request.Context(), req.Email, req.Password, req.TenantID)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			writeError(c, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")
			return
		}
		if errors.Is(err, domain.ErrTenantNotFound) || errors.Is(err, domain.ErrMembershipNotFound) {
			writeError(c, http.StatusForbidden, "no_tenant_access", "you do not have access to the specified tenant")
			return
		}
		if errors.Is(err, domain.ErrTenantSuspended) {
			writeError(c, http.StatusForbidden, "tenant_suspended", "the specified tenant is suspended")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to log in")
		return
	}
	c.JSON(http.StatusOK, toAuthResponse(result))
}

type switchTenantRequest struct {
	TenantID string `json:"tenant_id" binding:"required"`
}

// SwitchTenant issues a fresh tenant-scoped token for a tenant the caller
// already belongs to (PRD §6 tenant-switcher).
func (h *AuthHandler) SwitchTenant(c *gin.Context) {
	var req switchTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	userID, _ := c.Get(middleware.ContextUserID)
	id, _ := userID.(string)
	result, err := h.auth.SwitchTenant(c.Request.Context(), id, req.TenantID)
	if err != nil {
		if errors.Is(err, domain.ErrTenantNotFound) || errors.Is(err, domain.ErrMembershipNotFound) {
			writeError(c, http.StatusForbidden, "no_tenant_access", "you do not have access to the specified tenant")
			return
		}
		if errors.Is(err, domain.ErrTenantSuspended) {
			writeError(c, http.StatusForbidden, "tenant_suspended", "the specified tenant is suspended")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to switch tenant")
		return
	}
	c.JSON(http.StatusOK, toAuthResponse(result))
}

// writeError follows the PRD's §2 error-code contract: a machine-readable
// code plus a message field. Localized message resolution (Farsi) is a
// fast-follow once i18n resource bundles land.
func writeError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}
