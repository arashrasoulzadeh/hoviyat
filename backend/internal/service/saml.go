package service

import (
	"context"
	"errors"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

var (
	ErrSAMLProviderDisabled = errors.New("saml provider disabled")
)

type SAMLService struct {
	providers        domain.SAMLProviderRepository
	users            domain.UserRepository
	memberships      domain.MembershipRepository
	teams            domain.TeamRepository
	teamMemberships  domain.TeamMembershipRepository
	hasher           *PasswordHasher
	tokens           *TokenService
}

func NewSAMLService(
	providers domain.SAMLProviderRepository,
	users domain.UserRepository,
	memberships domain.MembershipRepository,
	teams domain.TeamRepository,
	teamMemberships domain.TeamMembershipRepository,
	hasher *PasswordHasher,
	tokens *TokenService,
) *SAMLService {
	return &SAMLService{
		providers:        providers,
		users:            users,
		memberships:      memberships,
		teams:            teams,
		teamMemberships:  teamMemberships,
		hasher:           hasher,
		tokens:           tokens,
	}
}

type SAMLProviderConfig struct {
	Name             string
	EntityID         string
	SSOURL           string
	SLOURL           string
	X509Cert         string
	PrivateKey       string
	AttributeMapping map[string]string
}

func (s *SAMLService) RegisterProvider(ctx context.Context, tenantID string, config SAMLProviderConfig) (*domain.SAMLProvider, error) {
	provider := &domain.SAMLProvider{
		TenantID:         tenantID,
		Name:             config.Name,
		EntityID:         config.EntityID,
		SSOURL:           config.SSOURL,
		SLOURL:           config.SLOURL,
		X509Cert:         config.X509Cert,
		PrivateKey:       config.PrivateKey,
		AttributeMapping: config.AttributeMapping,
		Enabled:          true,
	}
	if err := s.providers.Create(ctx, provider); err != nil {
		return nil, err
	}
	return provider, nil
}

func (s *SAMLService) GetProvider(ctx context.Context, id string) (*domain.SAMLProvider, error) {
	return s.providers.FindByID(ctx, id)
}

func (s *SAMLService) ListProviders(ctx context.Context, tenantID string) ([]*domain.SAMLProvider, error) {
	return s.providers.FindByTenant(ctx, tenantID)
}

func (s *SAMLService) UpdateProvider(ctx context.Context, provider *domain.SAMLProvider) error {
	return s.providers.Update(ctx, provider)
}

func (s *SAMLService) DeleteProvider(ctx context.Context, id string) error {
	return s.providers.Delete(ctx, id)
}

func (s *SAMLService) HandleACS(ctx context.Context, providerID string, samlResponse string) (*AuthResult, error) {
	// Placeholder for SAML ACS handling
	// TODO: Implement with crewjam/saml library
	return nil, errors.New("saml acs handling not yet implemented")
}

func (s *SAMLService) mapAttributes(provider *domain.SAMLProvider, attributes map[string][]string) map[string]string {
	result := make(map[string]string)
	for samlAttr, userField := range provider.AttributeMapping {
		if vals, ok := attributes[samlAttr]; ok && len(vals) > 0 {
			result[userField] = vals[0]
		}
	}
	return result
}

func (s *SAMLService) findOrCreateUser(ctx context.Context, tenantID string, attributes map[string]string) (*domain.User, error) {
	email := attributes["email"]
	if email == "" {
		return nil, errors.New("email not provided by SAML IdP")
	}

	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if !errors.Is(err, domain.ErrUserNotFound) {
			return nil, err
		}
		user = &domain.User{
			Email:        email,
			PasswordHash: "",
		}
		if err := s.users.Create(ctx, user); err != nil {
			return nil, err
		}
	}

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