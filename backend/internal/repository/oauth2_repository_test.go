package repository

import (
	"context"
	"testing"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeOAuth2ProviderRepository struct {
	byID       map[string]*domain.OAuth2Provider
	byTenant   map[string][]*domain.OAuth2Provider // tenantID -> providers
	byName     map[string]*domain.OAuth2Provider // tenantID|name -> provider
}

func newFakeOAuth2ProviderRepository() *fakeOAuth2ProviderRepository {
	return &fakeOAuth2ProviderRepository{
		byID:     make(map[string]*domain.OAuth2Provider),
		byTenant: make(map[string][]*domain.OAuth2Provider),
		byName:   make(map[string]*domain.OAuth2Provider),
	}
}

func (f *fakeOAuth2ProviderRepository) Create(_ context.Context, p *domain.OAuth2Provider) error {
	if p.ID == "" {
		p.ID = "oauth2-" + p.Name
	}
	if _, exists := f.byID[p.ID]; exists {
		return domain.ErrOAuth2ProviderNotFound
	}
	nameKey := p.TenantID + "|" + p.Name
	if _, exists := f.byName[nameKey]; exists {
		return domain.ErrOAuth2ProviderNotFound
	}
	f.byID[p.ID] = p
	f.byTenant[p.TenantID] = append(f.byTenant[p.TenantID], p)
	f.byName[nameKey] = p
	return nil
}

func (f *fakeOAuth2ProviderRepository) FindByID(_ context.Context, id string) (*domain.OAuth2Provider, error) {
	p, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrOAuth2ProviderNotFound
	}
	return p, nil
}

func (f *fakeOAuth2ProviderRepository) FindByTenant(_ context.Context, tenantID string) ([]*domain.OAuth2Provider, error) {
	return f.byTenant[tenantID], nil
}

func (f *fakeOAuth2ProviderRepository) FindByTenantAndName(_ context.Context, tenantID, name string) (*domain.OAuth2Provider, error) {
	p, ok := f.byName[tenantID+"|"+name]
	if !ok {
		return nil, domain.ErrOAuth2ProviderNotFound
	}
	return p, nil
}

func (f *fakeOAuth2ProviderRepository) Update(_ context.Context, p *domain.OAuth2Provider) error {
	if _, ok := f.byID[p.ID]; !ok {
		return domain.ErrOAuth2ProviderNotFound
	}
	f.byID[p.ID] = p
	// Update in byTenant slice
	for i, existing := range f.byTenant[p.TenantID] {
		if existing.ID == p.ID {
			f.byTenant[p.TenantID][i] = p
			break
		}
	}
	nameKey := p.TenantID + "|" + p.Name
	f.byName[nameKey] = p
	return nil
}

func (f *fakeOAuth2ProviderRepository) Delete(_ context.Context, id string) error {
	p, ok := f.byID[id]
	if !ok {
		return domain.ErrOAuth2ProviderNotFound
	}
	delete(f.byID, id)
	// Remove from byTenant
	providers := f.byTenant[p.TenantID]
	for i, existing := range providers {
		if existing.ID == id {
			f.byTenant[p.TenantID] = append(providers[:i], providers[i+1:]...)
			break
		}
	}
	delete(f.byName, p.TenantID+"|"+p.Name)
	return nil
}

func TestOAuth2ProviderRepository_Create(t *testing.T) {
	repo := newFakeOAuth2ProviderRepository()

	provider := &domain.OAuth2Provider{
		TenantID:     "tenant-1",
		Name:         "google",
		ClientID:     "client-123",
		ClientSecret: "secret-123",
		AuthURL:      "https://accounts.google.com/o/oauth2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
		Scopes:       []string{"openid", "profile", "email"},
		IssuerURL:    "https://accounts.google.com",
		ProviderType: "google",
		Enabled:      true,
	}

	err := repo.Create(context.Background(), provider)
	assert.NoError(t, err)
	assert.NotEmpty(t, provider.ID)
}

func TestOAuth2ProviderRepository_Create_DuplicateName(t *testing.T) {
	repo := newFakeOAuth2ProviderRepository()

	p1 := &domain.OAuth2Provider{TenantID: "tenant-1", Name: "google", ClientID: "c1", ClientSecret: "s1", ProviderType: "google"}
	p2 := &domain.OAuth2Provider{TenantID: "tenant-1", Name: "google", ClientID: "c2", ClientSecret: "s2", ProviderType: "google"}

	err := repo.Create(context.Background(), p1)
	require.NoError(t, err)

	err = repo.Create(context.Background(), p2)
	assert.ErrorIs(t, err, domain.ErrOAuth2ProviderNotFound)
}

func TestOAuth2ProviderRepository_FindByID(t *testing.T) {
	repo := newFakeOAuth2ProviderRepository()

	provider := &domain.OAuth2Provider{TenantID: "tenant-1", Name: "google", ClientID: "c1", ClientSecret: "s1", ProviderType: "google"}
	err := repo.Create(context.Background(), provider)
	require.NoError(t, err)

	found, err := repo.FindByID(context.Background(), provider.ID)
	assert.NoError(t, err)
	assert.Equal(t, provider.ID, found.ID)
}

func TestOAuth2ProviderRepository_FindByTenant(t *testing.T) {
	repo := newFakeOAuth2ProviderRepository()

	p1 := &domain.OAuth2Provider{TenantID: "tenant-1", Name: "google", ClientID: "c1", ClientSecret: "s1", ProviderType: "google"}
	p2 := &domain.OAuth2Provider{TenantID: "tenant-1", Name: "github", ClientID: "c2", ClientSecret: "s2", ProviderType: "github"}
	p3 := &domain.OAuth2Provider{TenantID: "tenant-2", Name: "google", ClientID: "c3", ClientSecret: "s3", ProviderType: "google"}

	repo.Create(context.Background(), p1)
	repo.Create(context.Background(), p2)
	repo.Create(context.Background(), p3)

	providers, err := repo.FindByTenant(context.Background(), "tenant-1")
	assert.NoError(t, err)
	assert.Len(t, providers, 2)
}

func TestOAuth2ProviderRepository_FindByTenantAndName(t *testing.T) {
	repo := newFakeOAuth2ProviderRepository()

	provider := &domain.OAuth2Provider{TenantID: "tenant-1", Name: "google", ClientID: "c1", ClientSecret: "s1", ProviderType: "google"}
	err := repo.Create(context.Background(), provider)
	require.NoError(t, err)

	found, err := repo.FindByTenantAndName(context.Background(), "tenant-1", "google")
	assert.NoError(t, err)
	assert.Equal(t, provider.ID, found.ID)
}

func TestOAuth2ProviderRepository_Update(t *testing.T) {
	repo := newFakeOAuth2ProviderRepository()

	provider := &domain.OAuth2Provider{TenantID: "tenant-1", Name: "google", ClientID: "c1", ClientSecret: "s1", ProviderType: "google", Enabled: true}
	err := repo.Create(context.Background(), provider)
	require.NoError(t, err)

	provider.Enabled = false
	err = repo.Update(context.Background(), provider)
	assert.NoError(t, err)

	found, err := repo.FindByID(context.Background(), provider.ID)
	assert.NoError(t, err)
	assert.False(t, found.Enabled)
}

func TestOAuth2ProviderRepository_Delete(t *testing.T) {
	repo := newFakeOAuth2ProviderRepository()

	provider := &domain.OAuth2Provider{TenantID: "tenant-1", Name: "google", ClientID: "c1", ClientSecret: "s1", ProviderType: "google"}
	err := repo.Create(context.Background(), provider)
	require.NoError(t, err)

	err = repo.Delete(context.Background(), provider.ID)
	assert.NoError(t, err)

	_, err = repo.FindByID(context.Background(), provider.ID)
	assert.ErrorIs(t, err, domain.ErrOAuth2ProviderNotFound)
}