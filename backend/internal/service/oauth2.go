package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

var (
	ErrInvalidOAuth2State   = errors.New("invalid oauth2 state")
	ErrPKCEVerification     = errors.New("pkce verification failed")
	ErrOAuth2ProviderDisabled = errors.New("oauth2 provider disabled")
)

type OAuth2Service struct {
	providers   domain.OAuth2ProviderRepository
	states      domain.OAuth2StateRepository
	users       domain.UserRepository
	memberships domain.MembershipRepository
	teams       domain.TeamRepository
	teamMemberships domain.TeamMembershipRepository
	hasher      *PasswordHasher
	tokens      *TokenService
	httpClient  *http.Client
}

func NewOAuth2Service(
	providers domain.OAuth2ProviderRepository,
	states domain.OAuth2StateRepository,
	users domain.UserRepository,
	memberships domain.MembershipRepository,
	teams domain.TeamRepository,
	teamMemberships domain.TeamMembershipRepository,
	hasher *PasswordHasher,
	tokens *TokenService,
) *OAuth2Service {
	return &OAuth2Service{
		providers:        providers,
		states:           states,
		users:            users,
		memberships:      memberships,
		teams:            teams,
		teamMemberships:  teamMemberships,
		hasher:           hasher,
		tokens:           tokens,
		httpClient:       &http.Client{Timeout: 10 * time.Second},
	}
}

type OAuth2ProviderConfig struct {
	Name           string
	ClientID       string
	ClientSecret   string
	AuthURL        string
	TokenURL       string
	UserInfoURL    string
	Scopes         []string
	IssuerURL      string
	ProviderType   string
}

func (s *OAuth2Service) RegisterProvider(ctx context.Context, tenantID string, config OAuth2ProviderConfig) (*domain.OAuth2Provider, error) {
	provider := &domain.OAuth2Provider{
		TenantID:     tenantID,
		Name:         config.Name,
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		AuthURL:      config.AuthURL,
		TokenURL:     config.TokenURL,
		UserInfoURL:  config.UserInfoURL,
		Scopes:       config.Scopes,
		IssuerURL:    config.IssuerURL,
		ProviderType: config.ProviderType,
		Enabled:      true,
	}
	if err := s.providers.Create(ctx, provider); err != nil {
		return nil, err
	}
	return provider, nil
}

func (s *OAuth2Service) GetProvider(ctx context.Context, id string) (*domain.OAuth2Provider, error) {
	return s.providers.FindByID(ctx, id)
}

func (s *OAuth2Service) ListProviders(ctx context.Context, tenantID string) ([]*domain.OAuth2Provider, error) {
	return s.providers.FindByTenant(ctx, tenantID)
}

func (s *OAuth2Service) UpdateProvider(ctx context.Context, provider *domain.OAuth2Provider) error {
	return s.providers.Update(ctx, provider)
}

func (s *OAuth2Service) DeleteProvider(ctx context.Context, id string) error {
	return s.providers.Delete(ctx, id)
}

func (s *OAuth2Service) GetAuthURL(ctx context.Context, tenantID, providerName, redirectURI string, pkce bool) (string, string, error) {
	provider, err := s.providers.FindByTenantAndName(ctx, tenantID, providerName)
	if err != nil {
		return "", "", err
	}
	if !provider.Enabled {
		return "", "", ErrOAuth2ProviderDisabled
	}

	state := generateRandomString(32)
	codeVerifier := ""
	codeChallenge := ""
	codeChallengeMethod := ""

	if pkce {
		codeVerifier = generateRandomString(64)
		codeChallenge = generateCodeChallenge(codeVerifier)
		codeChallengeMethod = "S256"
	}

	oauth2State := &domain.OAuth2State{
		State:                state,
		ProviderID:           provider.ID,
		TenantID:             tenantID,
		RedirectURI:          redirectURI,
		CodeChallenge:        codeVerifier,
		CodeChallengeMethod:  codeChallengeMethod,
		ExpiresAt:            time.Now().Add(10 * time.Minute),
	}
	if err := s.states.Create(ctx, oauth2State); err != nil {
		return "", "", err
	}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", provider.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	params.Set("scope", joinScopes(provider.Scopes))

	if codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", codeChallengeMethod)
	}

	authURL := provider.AuthURL + "?" + params.Encode()
	return authURL, state, nil
}

func (s *OAuth2Service) HandleCallback(ctx context.Context, state, code string) (*AuthResult, error) {
	oauth2State, err := s.states.FindByState(ctx, state)
	if err != nil || oauth2State == nil {
		return nil, ErrInvalidOAuth2State
	}
	if time.Now().After(oauth2State.ExpiresAt) {
		s.states.Delete(ctx, state)
		return nil, ErrInvalidOAuth2State
	}

	provider, err := s.providers.FindByID(ctx, oauth2State.ProviderID)
	if err != nil {
		return nil, err
	}

	tokenURL := provider.TokenURL
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", oauth2State.RedirectURI)
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", provider.ClientSecret)

	if oauth2State.CodeChallenge != "" {
		data.Set("code_verifier", oauth2State.CodeChallenge)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = data

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", resp.Status)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	// Get user info
	userInfo, err := s.getUserInfo(ctx, provider, tokenResp.AccessToken, tokenResp.IDToken)
	if err != nil {
		return nil, err
	}

	// Find or create user
	user, err := s.findOrCreateUser(ctx, provider.TenantID, userInfo)
	if err != nil {
		return nil, err
	}

	// Get roles for tenant
	roles, err := s.getRolesForTenant(ctx, user.ID, provider.TenantID)
	if err != nil {
		return nil, err
	}

	// Issue tokens
	result, err := s.issueTokens(user, provider.TenantID, roles)
	if err != nil {
		return nil, err
	}

	// Clean up state
	s.states.Delete(ctx, state)

	return result, nil
}

func (s *OAuth2Service) getUserInfo(ctx context.Context, provider *domain.OAuth2Provider, accessToken, idToken string) (map[string]interface{}, error) {
	// If OIDC with ID token, verify it
	if provider.ProviderType == "oidc" && provider.IssuerURL != "" && idToken != "" {
		oidcProvider, err := oidc.NewProvider(ctx, provider.IssuerURL)
		if err == nil {
			verifier := oidcProvider.Verifier(&oidc.Config{ClientID: provider.ClientID})
			idTokenClaims, err := verifier.Verify(ctx, idToken)
			if err == nil {
				var claims map[string]interface{}
				idTokenClaims.Claims(&claims)
				return claims, nil
			}
		}
	}

	// Fallback to userinfo endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", provider.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	return userInfo, nil
}

func (s *OAuth2Service) findOrCreateUser(ctx context.Context, tenantID string, userInfo map[string]interface{}) (*domain.User, error) {
	email, _ := userInfo["email"].(string)
	if email == "" {
		return nil, errors.New("email not provided by OAuth2 provider")
	}

	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if !errors.Is(err, domain.ErrUserNotFound) {
			return nil, err
		}
		// Create new user
		user = &domain.User{
			Email:        email,
			PasswordHash: "", // No password for OAuth2 users
		}
		if err := s.users.Create(ctx, user); err != nil {
			return nil, err
		}
	}

	// Ensure membership in tenant
	membership, err := s.memberships.FindByUserAndTenant(ctx, user.ID, tenantID)
	if err != nil {
		if errors.Is(err, domain.ErrMembershipNotFound) {
			membership = &domain.Membership{
				UserID:   user.ID,
				TenantID: tenantID,
				Roles:    []string{"member"},
			}
			if err := s.memberships.Create(ctx, membership); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return user, nil
}

func (s *OAuth2Service) getRolesForTenant(ctx context.Context, userID, tenantID string) ([]string, error) {
	membership, err := s.memberships.FindByUserAndTenant(ctx, userID, tenantID)
	if err != nil {
		return []string{}, err
	}
	roles := membership.Roles

	teamMemberships, err := s.teamMemberships.ListByUser(ctx, userID)
	if err != nil {
		return roles, nil
	}
	for _, tm := range teamMemberships {
		team, err := s.teams.FindByID(ctx, tm.TeamID)
		if err != nil {
			continue
		}
		if team.TenantID == tenantID {
			roles = append(roles, tm.Roles...)
		}
	}
	return roles, nil
}

func (s *OAuth2Service) issueTokens(user *domain.User, tenantID string, roles []string) (*AuthResult, error) {
	access, err := s.tokens.GenerateAccessToken(user.ID, tenantID, roles)
	if err != nil {
		return nil, err
	}
	refresh, err := s.tokens.GenerateRefreshToken(user.ID, tenantID, roles)
	if err != nil {
		return nil, err
	}
	return &AuthResult{
		AccessToken:  access,
		RefreshToken: refresh,
		User:         user,
		TenantID:     tenantID,
		Roles:        roles,
	}, nil
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:length]
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}