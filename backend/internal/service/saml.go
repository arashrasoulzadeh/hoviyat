package service

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

var (
	ErrSAMLProviderDisabled = errors.New("saml provider disabled")
)

type SAMLService struct {
	providers  domain.SAMLProviderRepository
	users      domain.UserRepository
	memberships domain.MembershipRepository
	teams      domain.TeamRepository
	teamMemberships domain.TeamMembershipRepository
	hasher     *PasswordHasher
	tokens     *TokenService
	serviceProviders map[string]*samlsp.Middleware
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
		providers:         providers,
		users:             users,
		memberships:       memberships,
		teams:             teams,
		teamMemberships:   teamMemberships,
		hasher:            hasher,
		tokens:            tokens,
		serviceProviders:  make(map[string]*samlsp.Middleware),
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

	// Build SAML SP middleware
	if err := s.buildServiceProvider(ctx, provider); err != nil {
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
	if err := s.providers.Update(ctx, provider); err != nil {
		return err
	}
	return s.buildServiceProvider(ctx, provider)
}

func (s *SAMLService) DeleteProvider(ctx context.Context, id string) error {
	delete(s.serviceProviders, id)
	return s.providers.Delete(ctx, id)
}

func (s *SAMLService) buildServiceProvider(ctx context.Context, provider *domain.SAMLProvider) error {
	// Parse certificate
	certBlock, _ := pem.Decode([]byte(provider.X509Cert))
	if certBlock == nil {
		return errors.New("invalid x509 certificate")
	}
	idpCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	// Parse private key
	keyBlock, _ := pem.Decode([]byte(provider.PrivateKey))
	if keyBlock == nil {
		return errors.New("invalid private key")
	}
	var privateKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}
		privateKey = key.(*rsa.PrivateKey)
	default:
		return errors.New("unsupported private key type")
	}

	// Build IdP metadata
	idpMetadata := &saml.EntityDescriptor{
		EntityID: provider.EntityID,
		IDPSSODescriptor: &saml.IDPSSODescriptor{
			KeyDescriptors: []saml.KeyDescriptor{
				{
					Use: "signing",
					KeyInfo: saml.KeyInfo{
						X509Data: saml.X509Data{
							X509Certificates: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBlock.Bytes}))},
						},
					},
				},
			},
			SingleSignOnServices: []saml.Endpoint{
				{Binding: saml.HTTPRedirectBinding, Location: provider.SSOURL},
			},
		},
	}
	if provider.SLOURL != "" {
		idpMetadata.IDPSSODescriptor.SingleLogoutServices = []saml.Endpoint{
			{Binding: saml.HTTPRedirectBinding, Location: provider.SLOURL},
		}
	}

	// Build SP metadata
	spMetadata := &saml.EntityDescriptor{
		EntityID: provider.EntityID + "/sp",
		SPSSODescriptor: &saml.SPSSODescriptor{
			AssertionConsumerServices: []saml.IndexedEndpoint{
				{Binding: saml.HTTPPostBinding, Location: provider.EntityID + "/acs", Index: 0},
			},
		},
	}

	sp, err := samlsp.New(samlsp.Options{
		EntityID:    provider.EntityID + "/sp",
		URL:         provider.EntityID,
		Key:         privateKey,
		Certificate: certBlock.Bytes,
		IDPMetadata: idpMetadata,
		SPMetadata:  spMetadata,
		ForceAuthn:  false,
		AllowIDPInitiated: true,
	})
	if err != nil {
		return fmt.Errorf("create saml sp: %w", err)
	}

	s.serviceProviders[provider.ID] = sp
	return nil
}

func (s *SAMLService) GetServiceProvider(providerID string) (*samlsp.Middleware, bool) {
	sp, ok := s.serviceProviders[providerID]
	return sp, ok
}

func (s *SAMLService) HandleACS(ctx context.Context, providerID string, samlResponse string) (*AuthResult, error) {
	provider, err := s.providers.FindByID(ctx, providerID)
	if err != nil {
		return nil, err
	}
	if !provider.Enabled {
		return nil, ErrSAMLProviderDisabled
	}

	sp, ok := s.serviceProviders[providerID]
	if !ok {
		return nil, errors.New("service provider not initialized")
	}

	// Parse SAML response
	// This would typically be done via the middleware's ServeHTTP
	// For now, we'll use the middleware's ParseResponse
	// In practice, this is handled by the HTTP handler
	return nil, errors.New("use HTTP handler for ACS")
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