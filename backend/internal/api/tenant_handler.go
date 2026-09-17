package api

import (
	"errors"
	"net/http"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

// TenantHandler exposes the tenant provisioning API (PRD §6:
// "Tenant provisioning API (create/suspend/delete tenant)"). It is a
// platform-operator-facing surface; RBAC/ABAC gating on these routes
// arrives with the ACL/ABAC build stage — for now they sit behind the
// same authenticated-request middleware as everything else.
type TenantHandler struct {
	tenants *service.TenantService
}

func NewTenantHandler(tenants *service.TenantService) *TenantHandler {
	return &TenantHandler{tenants: tenants}
}

type createTenantRequest struct {
	Name string `json:"name" binding:"required"`
	Slug string `json:"slug" binding:"required"`
}

func toTenantResponse(tenant *domain.Tenant) gin.H {
	return gin.H{
		"id":     tenant.ID,
		"name":   tenant.Name,
		"slug":   tenant.Slug,
		"status": tenant.Status,
	}
}

func (h *TenantHandler) Create(c *gin.Context) {
	var req createTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tenant, err := h.tenants.Create(c.Request.Context(), req.Name, req.Slug)
	if err != nil {
		if errors.Is(err, domain.ErrTenantAlreadyExists) {
			writeError(c, http.StatusConflict, "tenant_exists", "a tenant with this slug already exists")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to create tenant")
		return
	}
	c.JSON(http.StatusCreated, toTenantResponse(tenant))
}

func (h *TenantHandler) Suspend(c *gin.Context) {
	id := c.Param("id")
	if err := h.tenants.Suspend(c.Request.Context(), id); err != nil {
		if errors.Is(err, domain.ErrTenantNotFound) {
			writeError(c, http.StatusNotFound, "tenant_not_found", "tenant not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to suspend tenant")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TenantHandler) Reactivate(c *gin.Context) {
	id := c.Param("id")
	if err := h.tenants.Reactivate(c.Request.Context(), id); err != nil {
		if errors.Is(err, domain.ErrTenantNotFound) {
			writeError(c, http.StatusNotFound, "tenant_not_found", "tenant not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to reactivate tenant")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TenantHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.tenants.Delete(c.Request.Context(), id); err != nil {
		if errors.Is(err, domain.ErrTenantNotFound) {
			writeError(c, http.StatusNotFound, "tenant_not_found", "tenant not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to delete tenant")
		return
	}
	c.Status(http.StatusNoContent)
}
