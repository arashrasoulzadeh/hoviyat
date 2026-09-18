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
	ErrMagicLinkNotFound = errors.New("magic link not found")
	ErrMagicLinkExpired  = errors.New("magic link expired")
	ErrMagicLinkUsed     = errors.New("magic link already used")
)

type PasswordlessService struct {
	magicLinks    domain.MagicLinkRepository
	users         domain.UserRepository
	memberships   domain.MembershipRepository
	teams         domain.TeamRepository
	teamMemberships domain.TeamMembershipRepository
	tokens        *TokenService
	emailSender   EmailSender
}

type EmailSender interface {
	SendMagicLink(ctx context.Context, email, link string) error
	SendPasswordReset(ctx context.Context, email, link string) error
	SendEmailVerification(ctx context.Context, email, link string) error
	SendOTP(ctx context.Context, email, otp string) error
	SendSMS(ctx context.Context, phone, otp string) error
}

func NewPasswordlessService(
	magicLinks domain.MagicLinkRepository,
	users domain.UserRepository,
	memberships domain.MembershipRepository,
	teams domain.TeamRepository,
	teamMemberships domain.TeamMembershipRepository,
	tokens *TokenService,
	emailSender EmailSender,
) *PasswordlessService {
	return &PasswordlessService{
		magicLinks:     magicLinks,
		users:          users,
		memberships:    memberships,
		teams:          teams,
		teamMemberships: teamMemberships,
		tokens:         tokens,
		emailSender:    emailSender,
	}
}

func (s *PasswordlessService) CreateMagicLink(ctx context.Context, email, tenantID, baseURL string) (*domain.MagicLink, string, error) {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			// Don't reveal if user exists
			return nil, "", nil
		}
		return nil, "", err
	}

	// Check if user has membership in tenant
	_, err = s.memberships.FindByUserAndTenant(ctx, user.ID, tenantID)
	if err != nil {
		return nil, "", err
	}

	token := generateToken()
	magicLink := &domain.MagicLink{
		UserID:    user.ID,
		TenantID:  tenantID,
		Token:     token,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	if err := s.magicLinks.Create(ctx, magicLink); err != nil {
		return nil, "", err
	}

	link := baseURL + "/auth/magic-link?token=" + token
	return magicLink, link, nil
}

func (s *PasswordlessService) SendMagicLink(ctx context.Context, email, tenantID, baseURL string) error {
	magicLink, link, err := s.CreateMagicLink(ctx, email, tenantID, baseURL)
	if err != nil || magicLink == nil {
		return err
	}
	return s.emailSender.SendMagicLink(ctx, email, link)
}

func (s *PasswordlessService) VerifyMagicLink(ctx context.Context, token, tenantID string) (*AuthResult, error) {
	magicLink, err := s.magicLinks.FindByToken(ctx, token)
	if err != nil {
		return nil, err
	}
	if magicLink.TenantID != tenantID {
		return nil, ErrMagicLinkNotFound
	}

	// Mark as used
	if err := s.magicLinks.MarkUsed(ctx, magicLink.ID); err != nil {
		return nil, err
	}

	// Get user and issue tokens
	user, err := s.users.FindByID(ctx, magicLink.UserID)
	if err != nil {
		return nil, err
	}

	roles, err := s.getRolesForTenant(ctx, user.ID, tenantID)
	if err != nil {
		return nil, err
	}

	return s.issueTokens(user, tenantID, roles)
}

func (s *PasswordlessService) getRolesForTenant(ctx context.Context, userID, tenantID string) ([]string, error) {
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

func (s *PasswordlessService) issueTokens(user *domain.User, tenantID string, roles []string) (*AuthResult, error) {
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

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}