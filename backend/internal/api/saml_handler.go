package api

import (
	"errors"
	"net/http"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

type SAMLHandler struct {
	saml   *service.SAMLService
	tokens *service.TokenService
}

func NewSAMLHandler(saml *service.SAMLService, tokens *service.TokenService) *SAMLHandler {
	return &SAMLHandler{saml: saml, tokens: tokens}
}

type registerSAMLProviderRequest struct {
	Name             string            `json:"name" binding:"required"`
	EntityID         string            `json:"entity_id" binding:"required"`
	SSOURL           string            `json:"sso_url" binding:"required,url"`
	SLOURL           string            `json:"slo_url" binding:"omitempty,url"`
	X509Cert         string            `json:"x509_cert" binding:"required"`
	PrivateKey       string            `json:"private_key" binding:"required"`
	AttributeMapping map[string]string `json:"attribute_mapping"`
}

type samlProviderResponse struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	EntityID         string            `json:"entity_id"`
	SSOURL           string            `json:"sso_url"`
	SLOURL           string            `json:"slo_url"`
	AttributeMapping map[string]string `json:"attribute_mapping"`
	Enabled          bool              `json:"enabled"`
}

func toSAMLProviderResponse(p *domain.SAMLProvider) samlProviderResponse {
	return samlProviderResponse{
		ID:               p.ID,
		Name:             p.Name,
		EntityID:         p.EntityID,
		SSOURL:           p.SSOURL,
		SLOURL:           p.SLOURL,
		AttributeMapping: p.AttributeMapping,
		Enabled:          p.Enabled,
	}
}

func (h *SAMLHandler) RegisterProvider(c *gin.Context) {
	tenantID := c.Param("tenantId")
	var req registerSAMLProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	provider, err := h.saml.RegisterProvider(c.Request.Context(), tenantID, service.SAMLProviderConfig{
		Name:             req.Name,
		EntityID:         req.EntityID,
		SSOURL:           req.SSOURL,
		SLOURL:           req.SLOURL,
		X509Cert:         req.X509Cert,
		PrivateKey:       req.PrivateKey,
		AttributeMapping: req.AttributeMapping,
	})
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to register saml provider")
		return
	}
	c.JSON(http.StatusCreated, toSAMLProviderResponse(provider))
}

func (h *SAMLHandler) ListProviders(c *gin.Context) {
	tenantID := c.Param("tenantId")
	providers, err := h.saml.ListProviders(c.Request.Context(), tenantID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list providers")
		return
	}
	resp := make([]samlProviderResponse, 0, len(providers))
	for _, p := range providers {
		resp = append(resp, toSAMLProviderResponse(p))
	}
	c.JSON(http.StatusOK, resp)
}

func (h *SAMLHandler) GetProvider(c *gin.Context) {
	id := c.Param("id")
	provider, err := h.saml.GetProvider(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrSAMLProviderNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "provider not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to get provider")
		return
	}
	c.JSON(http.StatusOK, toSAMLProviderResponse(provider))
}

func (h *SAMLHandler) DeleteProvider(c *gin.Context) {
	id := c.Param("id")
	if err := h.saml.DeleteProvider(c.Request.Context(), id); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to delete provider")
		return
	}
	c.Status(http.StatusNoContent)
}

// Placeholder endpoints for SAML flow - full implementation requires SAML library integration
func (h *SAMLHandler) InitiateSSO(c *gin.Context) {
	writeError(c, http.StatusNotImplemented, "not_implemented", "saml sso not yet implemented")
}

func (h *SAMLHandler) ACS(c *gin.Context) {
	writeError(c, http.StatusNotImplemented, "not_implemented", "saml acs not yet implemented")
}

func (h *SAMLHandler) SLO(c *gin.Context) {
	writeError(c, http.StatusNotImplemented, "not_implemented", "saml slo not yet implemented")
}

func (h *SAMLHandler) Metadata(c *gin.Context) {
	writeError(c, http.StatusNotImplemented, "not_implemented", "saml metadata not yet implemented")
}