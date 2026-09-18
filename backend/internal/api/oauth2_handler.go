package api

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/middleware"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

type OAuth2Handler struct {
	oauth2 *service.OAuth2Service
	tokens *service.TokenService
}

func NewOAuth2Handler(oauth2 *service.OAuth2Service, tokens *service.TokenService) *OAuth2Handler {
	return &OAuth2Handler{oauth2: oauth2, tokens: tokens}
}

type registerProviderRequest struct {
	Name         string   `json:"name" binding:"required"`
	ClientID     string   `json:"client_id" binding:"required"`
	ClientSecret string   `json:"client_secret" binding:"required"`
	AuthURL      string   `json:"auth_url" binding:"required,url"`
	TokenURL     string   `json:"token_url" binding:"required,url"`
	UserInfoURL  string   `json:"user_info_url" binding:"required,url"`
	Scopes       []string `json:"scopes"`
	IssuerURL    string   `json:"issuer_url" binding:"omitempty,url"`
	ProviderType string   `json:"provider_type" binding:"required,oneof=google github oidc generic"`
}

type oauth2ProviderResponse struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	ClientID      string   `json:"client_id"`
	AuthURL       string   `json:"auth_url"`
	TokenURL      string   `json:"token_url"`
	UserInfoURL   string   `json:"user_info_url"`
	Scopes        []string `json:"scopes"`
	IssuerURL     string   `json:"issuer_url"`
	ProviderType  string   `json:"provider_type"`
	Enabled       bool     `json:"enabled"`
}

func toOAuth2ProviderResponse(p *domain.OAuth2Provider) oauth2ProviderResponse {
	return oauth2ProviderResponse{
		ID:           p.ID,
		Name:         p.Name,
		ClientID:     p.ClientID,
		AuthURL:      p.AuthURL,
		TokenURL:     p.TokenURL,
		UserInfoURL:  p.UserInfoURL,
		Scopes:       p.Scopes,
		IssuerURL:    p.IssuerURL,
		ProviderType: p.ProviderType,
		Enabled:      p.Enabled,
	}
}

func (h *OAuth2Handler) RegisterProvider(c *gin.Context) {
	tenantID := c.Param("tenantId")
	var req registerProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	provider, err := h.oauth2.RegisterProvider(c.Request.Context(), tenantID, service.OAuth2ProviderConfig{
		Name:           req.Name,
		ClientID:       req.ClientID,
		ClientSecret:   req.ClientSecret,
		AuthURL:        req.AuthURL,
		TokenURL:       req.TokenURL,
		UserInfoURL:    req.UserInfoURL,
		Scopes:         req.Scopes,
		IssuerURL:      req.IssuerURL,
		ProviderType:   req.ProviderType,
	})
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to register provider")
		return
	}
	c.JSON(http.StatusCreated, toOAuth2ProviderResponse(provider))
}

func (h *OAuth2Handler) ListProviders(c *gin.Context) {
	tenantID := c.Param("tenantId")
	providers, err := h.oauth2.ListProviders(c.Request.Context(), tenantID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list providers")
		return
	}
	resp := make([]oauth2ProviderResponse, 0, len(providers))
	for _, p := range providers {
		resp = append(resp, toOAuth2ProviderResponse(p))
	}
	c.JSON(http.StatusOK, resp)
}

func (h *OAuth2Handler) GetProvider(c *gin.Context) {
	id := c.Param("id")
	provider, err := h.oauth2.GetProvider(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrOAuth2ProviderNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "provider not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to get provider")
		return
	}
	c.JSON(http.StatusOK, toOAuth2ProviderResponse(provider))
}

func (h *OAuth2Handler) DeleteProvider(c *gin.Context) {
	id := c.Param("id")
	if err := h.oauth2.DeleteProvider(c.Request.Context(), id); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to delete provider")
		return
	}
	c.Status(http.StatusNoContent)
}

type authURLRequest struct {
	ProviderName string `json:"provider_name" binding:"required"`
	RedirectURI  string `json:"redirect_uri" binding:"required,url"`
	PKCE         bool   `json:"pkce"`
}

type authURLResponse struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
}

func (h *OAuth2Handler) GetAuthURL(c *gin.Context) {
	tenantID := c.Param("tenantId")
	var req authURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	authURL, state, err := h.oauth2.GetAuthURL(c.Request.Context(), tenantID, req.ProviderName, req.RedirectURI, req.PKCE)
	if err != nil {
		if errors.Is(err, service.ErrOAuth2ProviderDisabled) {
			writeError(c, http.StatusForbidden, "provider_disabled", "oauth2 provider is disabled")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to generate auth URL")
		return
	}
	c.JSON(http.StatusOK, authURLResponse{AuthURL: authURL, State: state})
}

type callbackRequest struct {
	State string `json:"state" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

func (h *OAuth2Handler) HandleCallback(c *gin.Context) {
	var req callbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	result, err := h.oauth2.HandleCallback(c.Request.Context(), req.State, req.Code)
	if err != nil {
		if errors.Is(err, service.ErrInvalidOAuth2State) {
			writeError(c, http.StatusBadRequest, "invalid_state", "invalid or expired oauth2 state")
			return
		}
		if errors.Is(err, service.ErrPKCEVerification) {
			writeError(c, http.StatusBadRequest, "pkce_failed", "pkce verification failed")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "oauth2 callback failed")
		return
	}
	c.JSON(http.StatusOK, toAuthResponse(result))
}

// RedirectCallback handles the OAuth2 redirect from the provider (for browser-based flows)
func (h *OAuth2Handler) RedirectCallback(c *gin.Context) {
	state := c.Query("state")
	code := c.Query("code")
	errorParam := c.Query("error")

	if errorParam != "" {
		errorDesc := c.Query("error_description")
		c.Redirect(http.StatusFound, "/login?error="+url.QueryEscape(errorParam)+"&error_description="+url.QueryEscape(errorDesc))
		return
	}

	if state == "" || code == "" {
		c.Redirect(http.StatusFound, "/login?error=invalid_callback")
		return
	}

	result, err := h.oauth2.HandleCallback(c.Request.Context(), state, code)
	if err != nil {
		c.Redirect(http.StatusFound, "/login?error=callback_failed")
		return
	}

	// Redirect to frontend with tokens (in practice, use a secure method)
	frontendURL := c.Query("frontend_url")
	if frontendURL == "" {
		frontendURL = "/auth/callback"
	}
	redirectURL := frontendURL + "?access_token=" + url.QueryEscape(result.AccessToken) + "&refresh_token=" + url.QueryEscape(result.RefreshToken)
	c.Redirect(http.StatusFound, redirectURL)
}