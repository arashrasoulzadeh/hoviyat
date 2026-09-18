package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

var (
	ErrSCIMUserNotFound      = errors.New("scim user not found")
	ErrSCIMGroupNotFound     = errors.New("scim group not found")
	ErrSCIMResourceConflict  = errors.New("scim resource conflict")
)

type SCIMUser struct {
	ID          string
	TenantID    string
	ExternalID  string
	UserName    string
	Name        SCIMName
	Emails      []SCIMEmail
	PhoneNumbers []SCIMPhoneNumber
	Addresses   []SCIMAddress
	Groups      []SCIMGroupRef
	Active      bool
	Created     time.Time
	Updated     time.Time
	Meta        SCIMMeta
}

type SCIMName struct {
	Formatted string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	MiddleName string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type SCIMPhoneNumber struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type SCIMAddress struct {
	Formatted string `json:"formatted,omitempty"`
	StreetAddress string `json:"streetAddress,omitempty"`
	Locality  string `json:"locality,omitempty"`
	Region    string `json:"region,omitempty"`
	PostalCode string `json:"postalCode,omitempty"`
	Country   string `json:"country,omitempty"`
	Type      string `json:"type,omitempty"`
	Primary   bool   `json:"primary,omitempty"`
}

type SCIMGroupRef struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

type SCIMGroup struct {
	ID          string
	TenantID    string
	ExternalID  string
	DisplayName string
	Members     []SCIMGroupMember
	Meta        SCIMMeta
}

type SCIMGroupMember struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

type SCIMService struct {
	users     domain.UserRepository
	memberships domain.MembershipRepository
	teams     domain.TeamRepository
	teamMemberships domain.TeamMembershipRepository
}

func NewSCIMService(
	users domain.UserRepository,
	memberships domain.MembershipRepository,
	teams domain.TeamRepository,
	teamMemberships domain.TeamMembershipRepository,
) *SCIMService {
	return &SCIMService{
		users:     users,
		memberships: memberships,
		teams:     teams,
		teamMemberships: teamMemberships,
	}
}

type SCIMUserFilter struct {
	Filter      string
	StartIndex  int
	Count       int
	Attributes  string
	ExcludedAttributes string
}

func (s *SCIMService) CreateUser(ctx context.Context, tenantID string, user *SCIMUser) (*SCIMUser, error) {
	// Check if user already exists by userName
	_, err := s.users.FindByEmail(ctx, user.UserName)
	if err == nil {
		return nil, ErrSCIMResourceConflict
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return nil, err
	}

	// Create internal user
	domainUser := &domain.User{
		Email:        user.UserName,
		PasswordHash: "", // SCIM users don't have passwords
	}
	if err := s.users.Create(ctx, domainUser); err != nil {
		return nil, err
	}

	// Create membership
	membership := &domain.Membership{
		UserID:   domainUser.ID,
		TenantID: tenantID,
		Roles:    []string{"member"},
	}
	if err := s.memberships.Create(ctx, membership); err != nil {
		return nil, err
	}

	// Convert to SCIM user
	scimUser := s.toSCIMUser(domainUser, tenantID)
	scimUser.ExternalID = user.ExternalID
	scimUser.Name = user.Name
	scimUser.Emails = user.Emails
	scimUser.PhoneNumbers = user.PhoneNumbers
	scimUser.Addresses = user.Addresses
	scimUser.Groups = user.Groups
	scimUser.Active = user.Active
	scimUser.Meta = SCIMMeta{
		ResourceType: "User",
		Created:      time.Now(),
		LastModified: time.Now(),
		Location:     fmt.Sprintf("/scim/v2/Users/%s", domainUser.ID),
	}

	return scimUser, nil
}

func (s *SCIMService) GetUser(ctx context.Context, tenantID, id string) (*SCIMUser, error) {
	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, ErrSCIMUserNotFound
		}
		return nil, err
	}

	// Verify membership
	_, err = s.memberships.FindByUserAndTenant(ctx, id, tenantID)
	if err != nil {
		return nil, ErrSCIMUserNotFound
	}

	return s.toSCIMUser(user, tenantID), nil
}

func (s *SCIMService) ListUsers(ctx context.Context, tenantID string, filter SCIMUserFilter) ([]*SCIMUser, int, error) {
	// In real implementation, would use filter for pagination and filtering
	// For now, return empty
	return []*SCIMUser{}, 0, nil
}

func (s *SCIMService) UpdateUser(ctx context.Context, tenantID, id string, user *SCIMUser) (*SCIMUser, error) {
	domainUser, err := s.users.FindByID(ctx, id)
	if err != nil {
		return nil, ErrSCIMUserNotFound
	}

	// Verify membership
	_, membershipErr := s.memberships.FindByUserAndTenant(ctx, id, tenantID)
	if membershipErr != nil {
		return nil, ErrSCIMUserNotFound
	}

	// In real implementation, would update user in database
	// For now, just return the SCIM user with updated fields
	scimUser := s.toSCIMUser(domainUser, tenantID)
	scimUser.ExternalID = user.ExternalID
	scimUser.Name = user.Name
	scimUser.Emails = user.Emails
	scimUser.PhoneNumbers = user.PhoneNumbers
	scimUser.Addresses = user.Addresses
	scimUser.Groups = user.Groups
	scimUser.Active = user.Active
	scimUser.Meta.LastModified = time.Now()

	return scimUser, nil
}

func (s *SCIMService) DeleteUser(ctx context.Context, tenantID, id string) error {
	_, userErr := s.users.FindByID(ctx, id)
	if userErr != nil {
		if errors.Is(userErr, domain.ErrUserNotFound) {
			return ErrSCIMUserNotFound
		}
		return userErr
	}

	// Verify membership
	_, membershipErr := s.memberships.FindByUserAndTenant(ctx, id, tenantID)
	if membershipErr != nil {
		return ErrSCIMUserNotFound
	}

	// Delete membership
	if err := s.memberships.Delete(ctx, id, tenantID); err != nil {
		return err
	}

	// In real implementation, might soft-delete user
	return nil
}

func (s *SCIMService) CreateGroup(ctx context.Context, tenantID string, group *SCIMGroup) (*SCIMGroup, error) {
	// In real implementation, would create group in database
	return nil, errors.New("not implemented")
}

func (s *SCIMService) GetGroup(ctx context.Context, tenantID, id string) (*SCIMGroup, error) {
	return nil, ErrSCIMGroupNotFound
}

func (s *SCIMService) ListGroups(ctx context.Context, tenantID string) ([]*SCIMGroup, error) {
	return []*SCIMGroup{}, nil
}

func (s *SCIMService) UpdateGroup(ctx context.Context, tenantID, id string, group *SCIMGroup) (*SCIMGroup, error) {
	return nil, ErrSCIMGroupNotFound
}

func (s *SCIMService) DeleteGroup(ctx context.Context, tenantID, id string) error {
	return ErrSCIMGroupNotFound
}

func (s *SCIMService) toSCIMUser(user *domain.User, tenantID string) *SCIMUser {
	nameParts := strings.SplitN(user.Email, "@", 2)
	givenName := nameParts[0]
	familyName := ""
	if len(nameParts) > 1 {
		familyName = nameParts[1]
	}

	emails := []SCIMEmail{
		{Value: user.Email, Type: "work", Primary: true},
	}

	return &SCIMUser{
		ID:        user.ID,
		TenantID:  tenantID,
		UserName:  user.Email,
		Name: SCIMName{
			Formatted: user.Email,
			GivenName:  givenName,
			FamilyName: familyName,
		},
		Emails:    emails,
		Active:    true,
		Created:   user.CreatedAt,
		Updated:   user.UpdatedAt,
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      user.CreatedAt,
			LastModified: user.UpdatedAt,
			Location:     fmt.Sprintf("/scim/v2/Users/%s", user.ID),
		},
	}
}