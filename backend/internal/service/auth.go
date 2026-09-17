package service

import (
	"context"
	"errors"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

// AuthService issues tenant-scoped sessions. Every token is minted for
// exactly one tenant context (PRD §6); a user with memberships in several
// tenants must authenticate (or switch) into a specific tenant to receive
// a token carrying that tenant's roles.
type AuthService struct {
	users       domain.UserRepository
	tenants     domain.TenantRepository
	memberships domain.MembershipRepository
	hasher      *PasswordHasher
	tokens      *TokenService
}

func NewAuthService(users domain.UserRepository, tenants domain.TenantRepository, memberships domain.MembershipRepository, hasher *PasswordHasher, tokens *TokenService) *AuthService {
	return &AuthService{users: users, tenants: tenants, memberships: memberships, hasher: hasher, tokens: tokens}
}

// AuthResult carries the caller's tenant-scoped session.
type AuthResult struct {
	AccessToken  string
	RefreshToken string
	User         *domain.User
	TenantID     string
	Roles        []string
}

// Register creates a new user and, when tenantID is provided, an initial
// membership in that tenant with the "admin" role (first member of a
// tenant provisions it). tenantID may be empty for a pre-tenant-selection
// account; the caller must then join or create a tenant before receiving a
// tenant-scoped token.
func (s *AuthService) Register(ctx context.Context, email, password, tenantID string) (*AuthResult, error) {
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	user := &domain.User{Email: email, PasswordHash: hash}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}

	var roles []string
	if tenantID != "" {
		tenant, err := s.tenants.FindByID(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		if tenant.Status != domain.TenantStatusActive {
			return nil, domain.ErrTenantSuspended
		}
		roles = []string{"admin"}
		membership := &domain.Membership{UserID: user.ID, TenantID: tenantID, Roles: roles}
		if err := s.memberships.Create(ctx, membership); err != nil {
			return nil, err
		}
	}

	return s.issueTokens(user, tenantID, roles)
}

// Login authenticates a user and, when tenantID is provided, loads that
// tenant's membership so the issued token carries the roles for that
// tenant only — never roles from any other tenant the user belongs to.
func (s *AuthService) Login(ctx context.Context, email, password, tenantID string) (*AuthResult, error) {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}
	if !s.hasher.Verify(user.PasswordHash, password) {
		return nil, domain.ErrInvalidCredentials
	}

	var roles []string
	if tenantID != "" {
		roles, err = s.rolesForTenant(ctx, user.ID, tenantID)
		if err != nil {
			return nil, err
		}
	}

	return s.issueTokens(user, tenantID, roles)
}

// SwitchTenant issues a fresh token scoped to a different tenant the user
// already belongs to. The previous token's roles are discarded entirely;
// only the target tenant's membership roles are used.
func (s *AuthService) SwitchTenant(ctx context.Context, userID, tenantID string) (*AuthResult, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	roles, err := s.rolesForTenant(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	return s.issueTokens(user, tenantID, roles)
}

func (s *AuthService) rolesForTenant(ctx context.Context, userID, tenantID string) ([]string, error) {
	tenant, err := s.tenants.FindByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant.Status != domain.TenantStatusActive {
		return nil, domain.ErrTenantSuspended
	}
	membership, err := s.memberships.FindByUserAndTenant(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	return membership.Roles, nil
}

func (s *AuthService) issueTokens(user *domain.User, tenantID string, roles []string) (*AuthResult, error) {
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
