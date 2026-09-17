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

func newTestRouter() (*gin.Engine, *fakeTenantRepository) {
	gin.SetMode(gin.TestMode)
	repo := newFakeUserRepository()
	tenants := newFakeTenantRepository()
	memberships := newFakeMembershipRepository()
	hasher := service.NewPasswordHasher()
	tokens := service.NewTokenService("test-secret", 15*time.Minute, 7*24*time.Hour)
	rbac := service.NewRBACService()
	authService := service.NewAuthService(repo, tenants, memberships, hasher, tokens)

	authHandler := api.NewAuthHandler(authService)
	userHandler := api.NewUserHandler(repo)
	return api.NewRouter(authHandler, userHandler, tokens, rbac), tenants
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
