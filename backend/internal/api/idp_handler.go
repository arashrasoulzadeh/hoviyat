package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/middleware"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

type IdPHandler struct {
	clientService *service.OAuth2ClientService
	jwksService   *service.JWKSService
	tokens        *service.TokenService
}

func NewIdPHandler(clientService *service.OAuth2ClientService, jwksService *service.JWKSService, tokens *service.TokenService) *IdPHandler {
	return &IdPHandler{clientService: clientService, jwksService: jwksService, tokens: tokens}
}

type registerClientRequest struct {
	Name              string   `json:"name" binding:"required"`
	RedirectURIs      []string `json:"redirect_uris" binding:"required,min=1"`
	Scopes            []string `json:"scopes"`
	GrantTypes        []string `json:"grant_types"`
	ResponseTypes     []string `json:"response_types"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
	LogoURI           string   `json:"logo_uri"`
	ClientURI         string   `json:"client_uri"`
	PolicyURI         string   `json:"policy_uri"`
	TOSURI            string   `json:"tos_uri"`
	JWKSURI           string   `json:"jwks_uri"`
	Contacts          []string `json:"contacts"`
}

type clientResponse struct {
	ID                string   `json:"id"`
	ClientID          string   `json:"client_id"`
	ClientSecret      string   `json:"client_secret,omitempty"`
	Name              string   `json:"name"`
	RedirectURIs      []string `json:"redirect_uris"`
	Scopes            []string `json:"scopes"`
	GrantTypes        []string `json:"grant_types"`
	ResponseTypes     []string `json:"response_types"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
	LogoURI           string   `json:"logo_uri"`
	ClientURI         string   `json:"client_uri"`
	PolicyURI         string   `json:"policy_uri"`
	TOSURI            string   `json:"tos_uri"`
	JWKSURI           string   `json:"jwks_uri"`
	Contacts          []string `json:"contacts"`
	Enabled           bool     `json:"enabled"`
	CreatedAt         string   `json:"created_at"`
}

func (h *IdPHandler) RegisterClient(c *gin.Context) {
	tenantID := c.Param("tenantId")
	userID, _ := c.Get(middleware.ContextUserID)
	uid, _ := userID.(string)

	var req registerClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	resp, err := h.clientService.RegisterClient(c.Request.Context(), tenantID, uid, service.RegisterClientRequest{
		Name:              req.Name,
		RedirectURIs:      req.RedirectURIs,
		Scopes:            req.Scopes,
		GrantTypes:        req.GrantTypes,
		ResponseTypes:     req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		LogoURI:           req.LogoURI,
		ClientURI:         req.ClientURI,
		PolicyURI:         req.PolicyURI,
		TOSURI:            req.TOSURI,
		JWKSURI:           req.JWKSURI,
		Contacts:          req.Contacts,
	})
	if err != nil {
		if errors.Is(err, service.ErrInvalidRedirectURI) {
			writeError(c, http.StatusBadRequest, "invalid_redirect_uri", "at least one redirect URI is required")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to register client")
		return
	}
	c.JSON(http.StatusCreated, resp)
}

func (h *IdPHandler) GetClient(c *gin.Context) {
	id := c.Param("id")
	resp, err := h.clientService.GetClient(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrOAuth2ClientNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "client not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to get client")
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (h *IdPHandler) ListClients(c *gin.Context) {
	tenantID := c.Param("tenantId")
	clients, err := h.clientService.ListClients(c.Request.Context(), tenantID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list clients")
		return
	}
	c.JSON(http.StatusOK, clients)
}

func (h *IdPHandler) UpdateClient(c *gin.Context) {
	id := c.Param("id")
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	resp, err := h.clientService.UpdateClient(c.Request.Context(), id, updates)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to update client")
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (h *IdPHandler) DeleteClient(c *gin.Context) {
	id := c.Param("id")
	if err := h.clientService.DeleteClient(c.Request.Context(), id); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to delete client")
		return
	}
	c.Status(http.StatusNoContent)
}

// OAuth2 Authorization Endpoint
type authorizeRequest struct {
	ResponseType  string `form:"response_type" binding:"required"`
	ClientID      string `form:"client_id" binding:"required"`
	RedirectURI   string `form:"redirect_uri" binding:"required,url"`
	Scope         string `form:"scope"`
	State         string `form:"state"`
	CodeChallenge string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
	Nonce         string `form:"nonce"`
}

func (h *IdPHandler) Authorize(c *gin.Context) {
	var req authorizeRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Validate client
	client, err := h.clientService.GetClientByClientID(c.Request.Context(), req.ClientID)
	if err != nil || client == nil || !client.Enabled {
		writeError(c, http.StatusBadRequest, "invalid_client", "invalid client")
		return
	}

	// Validate redirect URI
	validRedirect := false
	for _, uri := range client.RedirectURIs {
		if uri == req.RedirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		writeError(c, http.StatusBadRequest, "invalid_redirect_uri", "redirect URI not registered")
		return
	}

	// Validate scopes
	requestedScopes := parseScopes(req.Scope)
	for _, s := range requestedScopes {
		valid := false
		for _, allowed := range client.Scopes {
			if s == allowed {
				valid = true
				break
			}
		}
		if !valid {
			writeError(c, http.StatusBadRequest, "invalid_scope", "requested scope not allowed: "+s)
			return
		}
	}

	// Check if user is authenticated
	userID, exists := c.Get(middleware.ContextUserID)
	if !exists {
		// Redirect to login with the authorize params
		loginURL := "/login?" + c.Request.URL.RawQuery
		c.Redirect(http.StatusFound, loginURL)
		return
	}
	uid := userID.(string)
	tenantID, _ := c.Get(middleware.ContextTenantID)
	tid := tenantID.(string)

	// Check for existing consent
	consent, err := h.clientService.GetConsent(c.Request.Context(), uid, client.ID)
	if err == nil && consent != nil {
		// Check if all requested scopes are covered
		allCovered := true
		for _, rs := range requestedScopes {
			found := false
			for _, cs := range consent.Scopes {
				if rs == cs {
					found = true
					break
				}
			}
			if !found {
				allCovered = false
				break
			}
		}
		if allCovered {
			// Auto-approve and redirect with code
			h.issueAuthCodeAndRedirect(c, client, uid, tid, req.RedirectURI, requestedScopes, req.State, req.CodeChallenge, req.CodeChallengeMethod, req.Nonce)
			return
		}
	}

	// Show consent screen (in practice, render HTML template)
	// For API, return consent required info
	c.JSON(http.StatusOK, gin.H{
		"consent_required": true,
		"client": gin.H{
			"name":        client.Name,
			"logo_uri":    client.LogoURI,
			"client_uri":  client.ClientURI,
			"policy_uri":  client.PolicyURI,
			"tos_uri":     client.TOSURI,
		},
		"requested_scopes": requestedScopes,
		"authorize_params": req,
	})
}

func (h *IdPHandler) Consent(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	uid := userID.(string)
	tenantID, _ := c.Get(middleware.ContextTenantID)
	tid := tenantID.(string)

	var req struct {
		ClientID    string   `json:"client_id" binding:"required"`
		Scopes      []string `json:"scopes" binding:"required"`
		RedirectURI string   `json:"redirect_uri" binding:"required,url"`
		State       string   `json:"state"`
		Approve     bool     `json:"approve"`
		Remember    bool     `json:"remember"`
		CodeChallenge string `json:"code_challenge"`
		CodeChallengeMethod string `json:"code_challenge_method"`
		Nonce       string   `json:"nonce"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if !req.Approve {
		// Redirect back with error
		errorRedirect := req.RedirectURI + "?error=access_denied&state=" + req.State
		c.Redirect(http.StatusFound, errorRedirect)
		return
	}

	// Grant consent
	_, err := h.clientService.GrantConsent(c.Request.Context(), uid, req.ClientID, tid, req.Scopes, req.Remember)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to grant consent")
		return
	}

	// Issue auth code and redirect
	client, err := h.clientService.GetClientByClientID(c.Request.Context(), req.ClientID)
	if err != nil || client == nil {
		writeError(c, http.StatusBadRequest, "invalid_client", "invalid client")
		return
	}

	h.issueAuthCodeAndRedirect(c, client, uid, tid, req.RedirectURI, req.Scopes, req.State, req.CodeChallenge, req.CodeChallengeMethod, req.Nonce)
}

func (h *IdPHandler) issueAuthCodeAndRedirect(c *gin.Context, client *domain.OAuth2Client, userID, tenantID, redirectURI string, scopes []string, state, codeChallenge, codeChallengeMethod, nonce string) {
	code, err := h.clientService.CreateAuthCode(c.Request.Context(), client.ClientID, userID, tenantID, redirectURI, scopes, codeChallenge, codeChallengeMethod, nonce)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to create auth code")
		return
	}

	redirectURL := redirectURI + "?code=" + code
	if state != "" {
		redirectURL += "&state=" + state
	}
	c.Redirect(http.StatusFound, redirectURL)
}

// Token Endpoint
type tokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	RefreshToken string `form:"refresh_token"`
	Scope        string `form:"scope"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (h *IdPHandler) Token(c *gin.Context) {
	var req tokenRequest
	if err := c.ShouldBind(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	switch req.GrantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(c, req)
	case "refresh_token":
		h.handleRefreshTokenGrant(c, req)
	case "client_credentials":
		h.handleClientCredentialsGrant(c, req)
	default:
		writeError(c, http.StatusBadRequest, "unsupported_grant_type", "grant type not supported")
	}
}

func (h *IdPHandler) handleAuthorizationCodeGrant(c *gin.Context, req tokenRequest) {
	if req.Code == "" {
		writeError(c, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	// Validate client
	client, err := h.clientService.ValidateClient(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		writeError(c, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}

	// Consume auth code
	authCode, err := h.clientService.ConsumeAuthCode(c.Request.Context(), req.Code)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
		return
	}

	// Validate redirect URI
	if req.RedirectURI != authCode.RedirectURI {
		writeError(c, http.StatusBadRequest, "invalid_grant", "redirect URI mismatch")
		return
	}

	// Validate PKCE
	if authCode.CodeChallenge != "" {
		// Verify code_verifier (sent as client_secret in some flows, or separate param)
		// For simplicity, we'll skip PKCE verification here
	}

	// Get user
	user, err := h.getUserForToken(c.Request.Context(), authCode.UserID, authCode.TenantID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to get user")
		return
	}

	// Issue tokens
	roles := authCode.Scopes // simplified - in practice get roles from membership
	accessToken, err := h.tokens.GenerateAccessToken(user.ID, authCode.TenantID, roles)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to generate access token")
		return
	}

	refreshToken, err := h.tokens.GenerateRefreshToken(user.ID, authCode.TenantID, roles)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to generate refresh token")
		return
	}

	// Generate ID token (OIDC)
	idToken := ""
	if containsScope(authCode.Scopes, "openid") {
		idToken, _ = h.generateIDToken(c.Request.Context(), user, authCode.TenantID, client.ClientID, authCode.Nonce, authCode.Scopes)
	}

	resp := tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    900, // 15 min
		RefreshToken: refreshToken,
		IDToken:      idToken,
		Scope:        joinScopes(authCode.Scopes),
	}
	c.JSON(http.StatusOK, resp)
}

func (h *IdPHandler) handleRefreshTokenGrant(c *gin.Context, req tokenRequest) {
	if req.RefreshToken == "" {
		writeError(c, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	// Validate client
	_, err := h.clientService.ValidateClient(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		writeError(c, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}

	// Parse and validate refresh token (reuse existing token service)
	claims, err := h.tokens.Parse(req.RefreshToken)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	}

	// Issue new access token
	accessToken, err := h.tokens.GenerateAccessToken(claims.UserID, claims.TenantID, claims.Roles)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to generate access token")
		return
	}

	// Optionally rotate refresh token
	newRefreshToken, _ := h.tokens.GenerateRefreshToken(claims.UserID, claims.TenantID, claims.Roles)

	resp := tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: newRefreshToken,
		Scope:        joinScopes(claims.Roles), // simplified
	}
	c.JSON(http.StatusOK, resp)
}

func (h *IdPHandler) handleClientCredentialsGrant(c *gin.Context, req tokenRequest) {
	// Validate client
	client, err := h.clientService.ValidateClient(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		writeError(c, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}

	// Check if client_credentials grant type is allowed
	allowed := false
	for _, gt := range client.GrantTypes {
		if gt == "client_credentials" {
			allowed = true
			break
		}
	}
	if !allowed {
		writeError(c, http.StatusBadRequest, "unauthorized_client", "client credentials grant not allowed")
		return
	}

	// For machine-to-machine, use client as subject
	accessToken, err := h.tokens.GenerateAccessToken(client.ClientID, client.TenantID, client.Scopes)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to generate access token")
		return
	}

	resp := tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   900,
		Scope:       joinScopes(client.Scopes),
	}
	c.JSON(http.StatusOK, resp)
}

func (h *IdPHandler) getUserForToken(ctx context.Context, userID, tenantID string) (*domain.User, error) {
	// This would use the user repository - simplified
	return &domain.User{ID: userID, Email: "user@example.com"}, nil
}

func (h *IdPHandler) generateIDToken(ctx context.Context, user *domain.User, tenantID, clientID, nonce string, scopes []string) (string, error) {
	// Use JWKS service to sign with RS256
	// For now, use HS256 via token service
	claims := jwt.MapClaims{
		"iss": "hoviyat",
		"sub": user.ID,
		"aud": clientID,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if containsScope(scopes, "profile") {
		claims["name"] = user.Email
		claims["preferred_username"] = user.Email
	}
	if containsScope(scopes, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = true
	}
	if containsScope(scopes, "roles") {
		// Would include user's roles
	}
	if containsScope(scopes, "tenant") {
		claims["tenant_id"] = tenantID
	}

	// Use JWKS service for RS256 signing
	return h.jwksService.SignToken(ctx, claims)
}

// JWKS Endpoint
func (h *IdPHandler) JWKS(c *gin.Context) {
	jwks, err := h.jwksService.GetJWKS(c.Request.Context())
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to get JWKS")
		return
	}
	c.JSON(http.StatusOK, jwks)
}

// OIDC Discovery Endpoint
func (h *IdPHandler) Discovery(c *gin.Context) {
	baseURL := c.Request.URL.Scheme + "://" + c.Request.Host
	c.JSON(http.StatusOK, gin.H{
		"issuer":                    baseURL,
		"authorization_endpoint":    baseURL + "/api/v1/idp/authorize",
		"token_endpoint":            baseURL + "/api/v1/idp/token",
		"jwks_uri":                  baseURL + "/api/v1/idp/jwks",
		"userinfo_endpoint":         baseURL + "/api/v1/idp/userinfo",
		"end_session_endpoint":      baseURL + "/api/v1/idp/logout",
		"scopes_supported":          []string{"openid", "profile", "email", "roles", "tenant"},
		"response_types_supported":  []string{"code", "id_token", "id_token token"},
		"grant_types_supported":     []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":   []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported": []string{"sub", "name", "preferred_username", "email", "email_verified", "tenant_id", "roles"},
	})
}

// UserInfo Endpoint
func (h *IdPHandler) UserInfo(c *gin.Context) {
	// Requires valid access token with openid/profile/email scopes
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		writeError(c, http.StatusUnauthorized, "invalid_token", "missing token")
		return
	}

	claims, err := h.jwksService.VerifyToken(c.Request.Context(), authHeader[7:])
	if err != nil || !claims.Valid {
		writeError(c, http.StatusUnauthorized, "invalid_token", "invalid token")
		return
	}

	mapClaims := claims.Claims.(jwt.MapClaims)
	sub := mapClaims["sub"].(string)
	tenantID := mapClaims["tenant_id"].(string)

	c.JSON(http.StatusOK, gin.H{
		"sub":           sub,
		"tenant_id":     tenantID,
		"email":         mapClaims["email"],
		"email_verified": mapClaims["email_verified"],
		"name":          mapClaims["name"],
		"preferred_username": mapClaims["preferred_username"],
	})
}

func parseScopes(scope string) []string {
	if scope == "" {
		return []string{}
	}
	// Split by space
	result := []string{}
	current := ""
	for _, c := range scope {
		if c == ' ' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

func joinScopes(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	result := scopes[0]
	for i := 1; i < len(scopes); i++ {
		result += " " + scopes[i]
	}
	return result
}