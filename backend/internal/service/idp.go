package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

var (
	ErrOAuth2ClientNotFound = errors.New("oauth2 client not found")
	ErrInvalidClient        = errors.New("invalid client")
	ErrInvalidRedirectURI   = errors.New("invalid redirect uri")
	ErrInvalidScope         = errors.New("invalid scope")
	ErrConsentRequired      = errors.New("consent required")
)

type OAuth2ClientService struct {
	clients  domain.OAuth2ClientRepository
	codes    domain.OAuth2AuthorizationCodeRepository
	consents domain.OAuth2ConsentRepository
	keys     domain.SigningKeyRepository
}

func NewOAuth2ClientService(
	clients domain.OAuth2ClientRepository,
	codes domain.OAuth2AuthorizationCodeRepository,
	consents domain.OAuth2ConsentRepository,
	keys domain.SigningKeyRepository,
) *OAuth2ClientService {
	return &OAuth2ClientService{
		clients:  clients,
		codes:    codes,
		consents: consents,
		keys:     keys,
	}
}

type RegisterClientRequest struct {
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

type ClientResponse struct {
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

func toClientResponse(c *domain.OAuth2Client, includeSecret bool) ClientResponse {
	resp := ClientResponse{
		ID:                c.ID,
		ClientID:          c.ClientID,
		Name:              c.Name,
		RedirectURIs:      c.RedirectURIs,
		Scopes:            c.Scopes,
		GrantTypes:        c.GrantTypes,
		ResponseTypes:     c.ResponseTypes,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		LogoURI:           c.LogoURI,
		ClientURI:         c.ClientURI,
		PolicyURI:         c.PolicyURI,
		TOSURI:            c.TOSURI,
		JWKSURI:           c.JWKSURI,
		Contacts:          c.Contacts,
		Enabled:           c.Enabled,
		CreatedAt:         c.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if includeSecret {
		resp.ClientSecret = c.ClientSecret
	}
	return resp
}

func (s *OAuth2ClientService) RegisterClient(ctx context.Context, tenantID, userID string, req RegisterClientRequest) (*ClientResponse, error) {
	if len(req.RedirectURIs) == 0 {
		return nil, ErrInvalidRedirectURI
	}

	// Default scopes
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "roles", "tenant"}
	}

	// Default grant types
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}

	// Default response types
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	// Default auth method
	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}

	clientID := generateClientID()
	clientSecret := generateClientSecret()

	client := &domain.OAuth2Client{
		TenantID:          tenantID,
		Name:              req.Name,
		ClientID:          clientID,
		ClientSecret:      hashClientSecret(clientSecret),
		RedirectURIs:      req.RedirectURIs,
		Scopes:            scopes,
		GrantTypes:        grantTypes,
		ResponseTypes:     responseTypes,
		TokenEndpointAuthMethod: authMethod,
		LogoURI:           req.LogoURI,
		ClientURI:         req.ClientURI,
		PolicyURI:         req.PolicyURI,
		TOSURI:            req.TOSURI,
		JWKSURI:           req.JWKSURI,
		Contacts:          req.Contacts,
		Enabled:           true,
		CreatedBy:         userID,
	}

	if err := s.clients.Create(ctx, client); err != nil {
		return nil, err
	}

	resp := toClientResponse(client, true)
	return &resp, nil
}

func (s *OAuth2ClientService) GetClient(ctx context.Context, id string) (*ClientResponse, error) {
	client, err := s.clients.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrOAuth2ClientNotFound) {
			return nil, ErrOAuth2ClientNotFound
		}
		return nil, err
	}
	resp := toClientResponse(client, false)
	return &resp, nil
}

func (s *OAuth2ClientService) GetClientByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error) {
	return s.clients.FindByClientID(ctx, clientID)
}

func (s *OAuth2ClientService) ListClients(ctx context.Context, tenantID string) ([]*ClientResponse, error) {
	clients, err := s.clients.FindByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	resp := make([]*ClientResponse, 0, len(clients))
	for _, c := range clients {
		r := toClientResponse(c, false)
		resp = append(resp, &r)
	}
	return resp, nil
}

func (s *OAuth2ClientService) UpdateClient(ctx context.Context, id string, updates map[string]interface{}) (*ClientResponse, error) {
	client, err := s.clients.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply updates (simplified - in practice, handle each field)
	if name, ok := updates["name"].(string); ok {
		client.Name = name
	}
	if redirectURIs, ok := updates["redirect_uris"].([]string); ok {
		client.RedirectURIs = redirectURIs
	}
	if scopes, ok := updates["scopes"].([]string); ok {
		client.Scopes = scopes
	}
	if enabled, ok := updates["enabled"].(bool); ok {
		client.Enabled = enabled
	}

	if err := s.clients.Update(ctx, client); err != nil {
		return nil, err
	}

	resp := toClientResponse(client, false)
	return &resp, nil
}

func (s *OAuth2ClientService) DeleteClient(ctx context.Context, id string) error {
	return s.clients.Delete(ctx, id)
}

func (s *OAuth2ClientService) ValidateClient(ctx context.Context, clientID, clientSecret string) (*domain.OAuth2Client, error) {
	client, err := s.clients.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	if !client.Enabled {
		return nil, ErrInvalidClient
	}
	if !verifyClientSecret(client.ClientSecret, clientSecret) {
		return nil, ErrInvalidClient
	}
	return client, nil
}

func (s *OAuth2ClientService) CreateAuthCode(ctx context.Context, clientID, userID, tenantID, redirectURI string, scopes []string, codeChallenge, codeChallengeMethod, nonce string) (string, error) {
	code := generateAuthCode()
	authCode := &domain.OAuth2AuthorizationCode{
		ID:                   code,
		ClientID:             clientID,
		UserID:               userID,
		TenantID:             tenantID,
		RedirectURI:          redirectURI,
		Scopes:               scopes,
		CodeChallenge:        codeChallenge,
		CodeChallengeMethod:  codeChallengeMethod,
		Nonce:                nonce,
		ExpiresAt:            time.Now().Add(10 * time.Minute),
	}
	if err := s.codes.Create(ctx, authCode); err != nil {
		return "", err
	}
	return code, nil
}

func (s *OAuth2ClientService) ConsumeAuthCode(ctx context.Context, code string) (*domain.OAuth2AuthorizationCode, error) {
	authCode, err := s.codes.FindByCode(ctx, code)
	if err != nil || authCode == nil {
		return nil, errors.New("invalid or expired authorization code")
	}
	// Delete after use (one-time use)
	s.codes.Delete(ctx, code)
	return authCode, nil
}

func (s *OAuth2ClientService) GetConsent(ctx context.Context, userID, clientID string) (*domain.OAuth2Consent, error) {
	return s.consents.FindByUserAndClient(ctx, userID, clientID)
}

func (s *OAuth2ClientService) GrantConsent(ctx context.Context, userID, clientID, tenantID string, scopes []string, remember bool) (*domain.OAuth2Consent, error) {
	consent, err := s.consents.FindByUserAndClient(ctx, userID, clientID)
	if err != nil {
		return nil, err
	}

	var expiresAt *time.Time
	if !remember {
		// Expire in 30 days if not remembered
		exp := time.Now().Add(30 * 24 * time.Hour)
		expiresAt = &exp
	}

	if consent == nil {
		consent = &domain.OAuth2Consent{
			UserID:    userID,
			ClientID:  clientID,
			TenantID:  tenantID,
			Scopes:    scopes,
			ExpiresAt: expiresAt,
		}
		if err := s.consents.Create(ctx, consent); err != nil {
			return nil, err
		}
	} else {
		consent.Scopes = scopes
		consent.ExpiresAt = expiresAt
		if err := s.consents.Update(ctx, consent); err != nil {
			return nil, err
		}
	}
	return consent, nil
}

func (s *OAuth2ClientService) RevokeConsent(ctx context.Context, userID, clientID string) error {
	return s.consents.Delete(ctx, userID, clientID)
}

func (s *OAuth2ClientService) ListUserConsents(ctx context.Context, userID string) ([]*domain.OAuth2Consent, error) {
	return s.consents.FindByUser(ctx, userID)
}

func generateClientID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "hov_" + base64.URLEncoding.EncodeToString(b)[:20]
}

func generateClientSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func hashClientSecret(secret string) string {
	// In production, use bcrypt or argon2
	// For now, simple hash
	return "hashed_" + secret
}

func verifyClientSecret(hashed, plain string) bool {
	return hashed == "hashed_"+plain
}

func generateAuthCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}