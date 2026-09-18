package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
)

// fakeUserRepository is an in-memory domain.UserRepository for unit tests,
// avoiding a Postgres dependency for the auth-service business logic.
type fakeUserRepository struct {
	byEmail map[string]*domain.User
	nextID  int
}

func newFakeUserRepository() *fakeUserRepository {
	return &fakeUserRepository{byEmail: map[string]*domain.User{}}
}

func (f *fakeUserRepository) Create(_ context.Context, user *domain.User) error {
	if _, exists := f.byEmail[user.Email]; exists {
		return domain.ErrUserAlreadyExists
	}
	f.nextID++
	user.ID = string(rune('a' + f.nextID))
	f.byEmail[user.Email] = user
	return nil
}

func (f *fakeUserRepository) FindByEmail(_ context.Context, email string) (*domain.User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUserRepository) FindByID(_ context.Context, id string) (*domain.User, error) {
	for _, u := range f.byEmail {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

// fakeTenantRepository is an in-memory domain.TenantRepository for unit
// tests.
type fakeTenantRepository struct {
	byID map[string]*domain.Tenant
}

func newFakeTenantRepository() *fakeTenantRepository {
	return &fakeTenantRepository{byID: map[string]*domain.Tenant{}}
}

func (f *fakeTenantRepository) Create(_ context.Context, tenant *domain.Tenant) error {
	if _, exists := f.byID[tenant.ID]; exists {
		return domain.ErrTenantAlreadyExists
	}
	f.byID[tenant.ID] = tenant
	return nil
}

func (f *fakeTenantRepository) FindByID(_ context.Context, id string) (*domain.Tenant, error) {
	t, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrTenantNotFound
	}
	return t, nil
}

func (f *fakeTenantRepository) FindBySlug(_ context.Context, slug string) (*domain.Tenant, error) {
	for _, t := range f.byID {
		if t.Slug == slug {
			return t, nil
		}
	}
	return nil, domain.ErrTenantNotFound
}

func (f *fakeTenantRepository) UpdateStatus(_ context.Context, id string, status domain.TenantStatus) error {
	t, ok := f.byID[id]
	if !ok {
		return domain.ErrTenantNotFound
	}
	t.Status = status
	return nil
}

func (f *fakeTenantRepository) Delete(_ context.Context, id string) error {
	delete(f.byID, id)
	return nil
}

// fakeMembershipRepository is an in-memory domain.MembershipRepository for
// unit tests.
type fakeMembershipRepository struct {
	byKey map[string]*domain.Membership
}

func newFakeMembershipRepository() *fakeMembershipRepository {
	return &fakeMembershipRepository{byKey: map[string]*domain.Membership{}}
}

func membershipKey(userID, tenantID string) string {
	return userID + "|" + tenantID
}

func (f *fakeMembershipRepository) Create(_ context.Context, membership *domain.Membership) error {
	key := membershipKey(membership.UserID, membership.TenantID)
	if _, exists := f.byKey[key]; exists {
		return domain.ErrMembershipAlreadyExists
	}
	f.byKey[key] = membership
	return nil
}

func (f *fakeMembershipRepository) FindByUserAndTenant(_ context.Context, userID, tenantID string) (*domain.Membership, error) {
	m, ok := f.byKey[membershipKey(userID, tenantID)]
	if !ok {
		return nil, domain.ErrMembershipNotFound
	}
	return m, nil
}

func (f *fakeMembershipRepository) ListByUser(_ context.Context, userID string) ([]*domain.Membership, error) {
	var out []*domain.Membership
	for _, m := range f.byKey {
		if m.UserID == userID {
			out = append(out, m)
		}
	}
	return out, nil
}

func (f *fakeMembershipRepository) UpdateRoles(_ context.Context, userID, tenantID string, roles []string) error {
	m, ok := f.byKey[membershipKey(userID, tenantID)]
	if !ok {
		return domain.ErrMembershipNotFound
	}
	m.Roles = roles
	return nil
}

func (f *fakeMembershipRepository) Delete(_ context.Context, userID, tenantID string) error {
	delete(f.byKey, membershipKey(userID, tenantID))
	return nil
}

type fakeTeamRepository struct {
	byID map[string]*domain.Team
}

func newFakeTeamRepository() *fakeTeamRepository {
	return &fakeTeamRepository{byID: map[string]*domain.Team{}}
}

func (f *fakeTeamRepository) Create(_ context.Context, team *domain.Team) error {
	if _, exists := f.byID[team.ID]; exists {
		return domain.ErrTeamAlreadyExists
	}
	f.byID[team.ID] = team
	return nil
}

func (f *fakeTeamRepository) FindByID(_ context.Context, id string) (*domain.Team, error) {
	t, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrTeamNotFound
	}
	return t, nil
}

func (f *fakeTeamRepository) FindBySlug(_ context.Context, tenantID, slug string) (*domain.Team, error) {
	for _, t := range f.byID {
		if t.TenantID == tenantID && t.Slug == slug {
			return t, nil
		}
	}
	return nil, domain.ErrTeamNotFound
}

func (f *fakeTeamRepository) ListByTenant(_ context.Context, tenantID string) ([]*domain.Team, error) {
	var out []*domain.Team
	for _, t := range f.byID {
		if t.TenantID == tenantID {
			out = append(out, t)
		}
	}
	return out, nil
}

func (f *fakeTeamRepository) Update(_ context.Context, team *domain.Team) error {
	if _, ok := f.byID[team.ID]; !ok {
		return domain.ErrTeamNotFound
	}
	f.byID[team.ID] = team
	return nil
}

func (f *fakeTeamRepository) Delete(_ context.Context, id string) error {
	delete(f.byID, id)
	return nil
}

type fakeTeamMembershipRepository struct {
	byKey map[string]*domain.TeamMembership
}

func newFakeTeamMembershipRepository() *fakeTeamMembershipRepository {
	return &fakeTeamMembershipRepository{byKey: map[string]*domain.TeamMembership{}}
}

func teamMembershipKey(userID, teamID string) string {
	return userID + "|" + teamID
}

func (f *fakeTeamMembershipRepository) Create(_ context.Context, tm *domain.TeamMembership) error {
	key := teamMembershipKey(tm.UserID, tm.TeamID)
	if _, exists := f.byKey[key]; exists {
		return domain.ErrTeamMembershipAlreadyExists
	}
	f.byKey[key] = tm
	return nil
}

func (f *fakeTeamMembershipRepository) FindByUserAndTeam(_ context.Context, userID, teamID string) (*domain.TeamMembership, error) {
	m, ok := f.byKey[teamMembershipKey(userID, teamID)]
	if !ok {
		return nil, domain.ErrTeamMembershipNotFound
	}
	return m, nil
}

func (f *fakeTeamMembershipRepository) ListByUser(_ context.Context, userID string) ([]*domain.TeamMembership, error) {
	var out []*domain.TeamMembership
	for _, m := range f.byKey {
		if m.UserID == userID {
			out = append(out, m)
		}
	}
	return out, nil
}

func (f *fakeTeamMembershipRepository) ListByTeam(_ context.Context, teamID string) ([]*domain.TeamMembership, error) {
	var out []*domain.TeamMembership
	for _, m := range f.byKey {
		if m.TeamID == teamID {
			out = append(out, m)
		}
	}
	return out, nil
}

func (f *fakeTeamMembershipRepository) UpdateRoles(_ context.Context, userID, teamID string, roles []string) error {
	m, ok := f.byKey[teamMembershipKey(userID, teamID)]
	if !ok {
		return domain.ErrTeamMembershipNotFound
	}
	m.Roles = roles
	return nil
}

func (f *fakeTeamMembershipRepository) Delete(_ context.Context, userID, teamID string) error {
	delete(f.byKey, teamMembershipKey(userID, teamID))
	return nil
}

func newTestAuthService() *service.AuthService {
	repo := newFakeUserRepository()
	tenants := newFakeTenantRepository()
	memberships := newFakeMembershipRepository()
	teams := newFakeTeamRepository()
	teamMemberships := newFakeTeamMembershipRepository()
	hasher := service.NewPasswordHasher()
	tokens := service.NewTokenService("test-secret", 15*time.Minute, 7*24*time.Hour)
	return service.NewAuthService(repo, tenants, memberships, teamMemberships, teams, hasher, tokens)
}

func TestRegisterAndLogin(t *testing.T) {
	auth := newTestAuthService()
	ctx := context.Background()

	regResult, err := auth.Register(ctx, "alice@example.com", "correct-horse-battery", "")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if regResult.AccessToken == "" || regResult.RefreshToken == "" {
		t.Fatal("Register() did not return tokens")
	}

	loginResult, err := auth.Login(ctx, "alice@example.com", "correct-horse-battery", "")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if loginResult.User.Email != "alice@example.com" {
		t.Fatalf("Login() email = %q, want alice@example.com", loginResult.User.Email)
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	auth := newTestAuthService()
	ctx := context.Background()

	if _, err := auth.Register(ctx, "bob@example.com", "correct-horse-battery", ""); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	_, err := auth.Register(ctx, "bob@example.com", "another-password", "")
	if !errors.Is(err, domain.ErrUserAlreadyExists) {
		t.Fatalf("Register() error = %v, want ErrUserAlreadyExists", err)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	auth := newTestAuthService()
	ctx := context.Background()

	if _, err := auth.Register(ctx, "carol@example.com", "correct-horse-battery", ""); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	_, err := auth.Login(ctx, "carol@example.com", "wrong-password", "")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginUnknownUser(t *testing.T) {
	auth := newTestAuthService()
	_, err := auth.Login(context.Background(), "nobody@example.com", "whatever12", "")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want ErrInvalidCredentials", err)
	}
}
