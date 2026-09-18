package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/api"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/middleware"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/repository"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

// fakeUserRepository mirrors internal/service's test double; kept local
// since it's unexported there and this is a different package.
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

// fakeTenantRepository and fakeMembershipRepository mirror the doubles in
// internal/service's tests; kept local since those are unexported there.
type fakeTenantRepository struct {
	byID   map[string]*domain.Tenant
	nextID int
}

func newFakeTenantRepository() *fakeTenantRepository {
	return &fakeTenantRepository{byID: map[string]*domain.Tenant{}}
}

func (f *fakeTenantRepository) Create(_ context.Context, tenant *domain.Tenant) error {
	if tenant.ID == "" {
		f.nextID++
		tenant.ID = string(rune('A' + f.nextID))
	}
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
	byID   map[string]*domain.Team
	nextID int
}

func newFakeTeamRepository() *fakeTeamRepository {
	return &fakeTeamRepository{byID: map[string]*domain.Team{}}
}

func (f *fakeTeamRepository) Create(_ context.Context, team *domain.Team) error {
	if team.ID == "" {
		f.nextID++
		team.ID = string(rune('T' + f.nextID))
	}
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

func newTestRouter() (*gin.Engine, *fakeTenantRepository) {
	gin.SetMode(gin.TestMode)
	repo := newFakeUserRepository()
	tenants := newFakeTenantRepository()
	memberships := newFakeMembershipRepository()
	teams := newFakeTeamRepository()
	teamMemberships := newFakeTeamMembershipRepository()
	hasher := service.NewPasswordHasher()
	tokens := service.NewTokenService("test-secret", 15*time.Minute, 7*24*time.Hour)
	rbac := service.NewRBACService()
	authService := service.NewAuthService(repo, tenants, memberships, teamMemberships, teams, hasher, tokens)

	authHandler := api.NewAuthHandler(authService)
	userHandler := api.NewUserHandler(repo, memberships, teamMemberships, teams)
	tenantService := service.NewTenantService(tenants)
	riskScorer := service.NewRiskScorer()
	tenantHandler := api.NewTenantHandler(tenantService, riskScorer)
	teamService := service.NewTeamService(teams)
	teamMembershipService := service.NewTeamMembershipService(teamMemberships, teams)
	teamHandler := api.NewTeamHandler(teamService, teamMembershipService)

	aclRepo := repository.NewACLRepository(nil)
	rolePermRepo := repository.NewRolePermissionRepository(nil)
	permRepo := repository.NewPermissionRepository(nil)
	policyRepo := repository.NewPolicyRepository(nil)

	aclService := service.NewACLService(aclRepo)
	rolePermService := service.NewRolePermissionService(rolePermRepo)
	permService := service.NewPermissionService(permRepo)
	policyService := service.NewPolicyService(policyRepo)
	abacService := service.NewABACService()
	authzService := service.NewAuthorizationService(
		rbac, aclService, abacService, rolePermService, policyService,
		nil, // cache not needed for tests
		memberships, teamMemberships, teams,
	)
	authzHandler := api.NewAuthzHandler(authzService, policyService, aclService, rolePermService, permService)

	tenantSignupLimiter := middleware.NewTenantSignupRateLimiter(100, time.Hour)
	return api.NewRouter(authHandler, userHandler, tenantHandler, teamHandler, authzHandler, tokens, rbac, tenantSignupLimiter), tenants
}

func doJSON(router http.Handler, method, path string, body any, bearer string) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestRegisterLoginAndMe(t *testing.T) {
	router, tenants := newTestRouter()
	tenant := &domain.Tenant{ID: "tenant-1", Name: "Acme", Slug: "acme", Status: domain.TenantStatusActive}
	if err := tenants.Create(context.Background(), tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	regRec := doJSON(router, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"email":     "dana@example.com",
		"password":  "correct-horse-battery",
		"tenant_id": tenant.ID,
	}, "")
	if regRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", regRec.Code, regRec.Body.String())
	}
	var reg struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(regRec.Body.Bytes(), &reg); err != nil {
		t.Fatalf("decode register response: %v", err)
	}

	meRec := doJSON(router, http.MethodGet, "/api/v1/users/me", nil, reg.AccessToken)
	if meRec.Code != http.StatusOK {
		t.Fatalf("me status = %d, body = %s", meRec.Code, meRec.Body.String())
	}
	var me struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(meRec.Body.Bytes(), &me); err != nil {
		t.Fatalf("decode me response: %v", err)
	}
	if me.Email != "dana@example.com" {
		t.Fatalf("me.Email = %q, want dana@example.com", me.Email)
	}
}

func TestMeRequiresAuth(t *testing.T) {
	router, _ := newTestRouter()
	rec := doJSON(router, http.MethodGet, "/api/v1/users/me", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	router, _ := newTestRouter()
	doJSON(router, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"email":    "erin@example.com",
		"password": "correct-horse-battery",
	}, "")

	rec := doJSON(router, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email":    "erin@example.com",
		"password": "wrong-password",
	}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestTenantProvisioningAndSwitch(t *testing.T) {
	router, _ := newTestRouter()

	regRec := doJSON(router, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"email":    "frank@example.com",
		"password": "correct-horse-battery",
	}, "")
	if regRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", regRec.Code, regRec.Body.String())
	}
	var reg struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(regRec.Body.Bytes(), &reg); err != nil {
		t.Fatalf("decode register response: %v", err)
	}

	createRec := doJSON(router, http.MethodPost, "/api/v1/tenants", map[string]string{
		"name":  "Acme Inc",
		"slug":  "acme-inc",
		"email": "frank@example.com",
	}, "")
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create tenant status = %d, body = %s", createRec.Code, createRec.Body.String())
	}
	var tenant struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &tenant); err != nil {
		t.Fatalf("decode create-tenant response: %v", err)
	}
	if tenant.ID == "" {
		t.Fatal("create tenant response missing id")
	}

	suspendRec := doJSON(router, http.MethodPost, "/api/v1/tenants/"+tenant.ID+"/suspend", nil, reg.AccessToken)
	if suspendRec.Code != http.StatusNoContent {
		t.Fatalf("suspend tenant status = %d, body = %s", suspendRec.Code, suspendRec.Body.String())
	}

	reactivateRec := doJSON(router, http.MethodPost, "/api/v1/tenants/"+tenant.ID+"/reactivate", nil, reg.AccessToken)
	if reactivateRec.Code != http.StatusNoContent {
		t.Fatalf("reactivate tenant status = %d, body = %s", reactivateRec.Code, reactivateRec.Body.String())
	}

	// A second user joins the newly-created tenant at registration time
	// (first member of a tenant provisions it with the admin role), then
	// switches into it to receive a tenant-scoped token.
	memberRegRec := doJSON(router, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"email":     "gina@example.com",
		"password":  "correct-horse-battery",
		"tenant_id": tenant.ID,
	}, "")
	if memberRegRec.Code != http.StatusCreated {
		t.Fatalf("member register status = %d, body = %s", memberRegRec.Code, memberRegRec.Body.String())
	}
	var memberReg struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(memberRegRec.Body.Bytes(), &memberReg); err != nil {
		t.Fatalf("decode member register response: %v", err)
	}

	switchRec := doJSON(router, http.MethodPost, "/api/v1/auth/switch-tenant", map[string]string{
		"tenant_id": tenant.ID,
	}, memberReg.AccessToken)
	if switchRec.Code != http.StatusOK {
		t.Fatalf("switch-tenant status = %d, body = %s", switchRec.Code, switchRec.Body.String())
	}
	var switched struct {
		TenantID string   `json:"tenant_id"`
		Roles    []string `json:"roles"`
	}
	if err := json.Unmarshal(switchRec.Body.Bytes(), &switched); err != nil {
		t.Fatalf("decode switch-tenant response: %v", err)
	}
	if switched.TenantID != tenant.ID {
		t.Fatalf("switch-tenant tenant_id = %q, want %q", switched.TenantID, tenant.ID)
	}
	if len(switched.Roles) != 1 || switched.Roles[0] != "admin" {
		t.Fatalf("switch-tenant roles = %v, want [admin]", switched.Roles)
	}
}

func TestSwitchTenantRequiresAuth(t *testing.T) {
	router, _ := newTestRouter()
	rec := doJSON(router, http.MethodPost, "/api/v1/auth/switch-tenant", map[string]string{
		"tenant_id": "some-tenant",
	}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
