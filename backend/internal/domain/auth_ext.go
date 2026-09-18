package domain

import (
	"context"
	"errors"
	"time"
)

// OAuth2Provider represents an external OAuth2/OIDC identity provider configuration.
type OAuth2Provider struct {
	ID              string
	TenantID        string
	Name            string
	ClientID        string
	ClientSecret    string // encrypted at rest
	AuthURL         string
	TokenURL        string
	UserInfoURL     string
	Scopes          []string
	IssuerURL       string // for OIDC discovery
	ProviderType    string // "google", "github", "oidc", "generic"
	Enabled         bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

var (
	ErrOAuth2ProviderNotFound = errors.New("oauth2 provider not found")
)

type OAuth2ProviderRepository interface {
	Create(ctx context.Context, p *OAuth2Provider) error
	FindByID(ctx context.Context, id string) (*OAuth2Provider, error)
	FindByTenant(ctx context.Context, tenantID string) ([]*OAuth2Provider, error)
	FindByTenantAndName(ctx context.Context, tenantID, name string) (*OAuth2Provider, error)
	Update(ctx context.Context, p *OAuth2Provider) error
	Delete(ctx context.Context, id string) error
}

// OAuth2State represents a CSRF state token for OAuth2 flows.
type OAuth2State struct {
	ID          string
	State       string
	ProviderID  string
	TenantID    string
	RedirectURI string
	CodeChallenge string // PKCE
	CodeChallengeMethod string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

type OAuth2StateRepository interface {
	Create(ctx context.Context, s *OAuth2State) error
	FindByState(ctx context.Context, state string) (*OAuth2State, error)
	Delete(ctx context.Context, state string) error
	DeleteExpired(ctx context.Context) error
}

// SAMLProvider represents a SAML 2.0 Identity Provider configuration.
type SAMLProvider struct {
	ID                  string
	TenantID            string
	Name                string
	EntityID            string
	SSOURL              string
	SLOURL              string
	X509Cert            string
	PrivateKey          string // encrypted at rest
	AttributeMapping    map[string]string // SAML attribute -> user field
	Enabled             bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

var (
	ErrSAMLProviderNotFound = errors.New("saml provider not found")
)

type SAMLProviderRepository interface {
	Create(ctx context.Context, p *SAMLProvider) error
	FindByID(ctx context.Context, id string) (*SAMLProvider, error)
	FindByTenant(ctx context.Context, tenantID string) ([]*SAMLProvider, error)
	Update(ctx context.Context, p *SAMLProvider) error
	Delete(ctx context.Context, id string) error
}

// MFAMethod represents a user's enrolled MFA method.
type MFAMethod struct {
	ID           string
	UserID       string
	TenantID     string
	Type         string // "totp", "email_otp", "sms_otp", "webauthn"
	Name         string // user-friendly name
	Secret       string // encrypted TOTP secret or WebAuthn credential ID
	BackupCodes  []string // encrypted backup codes (for TOTP)
	IsPrimary    bool
	VerifiedAt   *time.Time
	LastUsedAt   *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

var (
	ErrMFAMethodNotFound = errors.New("mfa method not found")
)

type MFAMethodRepository interface {
	Create(ctx context.Context, m *MFAMethod) error
	FindByID(ctx context.Context, id string) (*MFAMethod, error)
	FindByUser(ctx context.Context, userID string) ([]*MFAMethod, error)
	FindPrimaryByUser(ctx context.Context, userID string) (*MFAMethod, error)
	Update(ctx context.Context, m *MFAMethod) error
	Delete(ctx context.Context, id string) error
}

// WebAuthnCredential represents a WebAuthn/Passkey credential.
type WebAuthnCredential struct {
	ID              string
	UserID          string
	TenantID        string
	CredentialID    string
	PublicKey       string
	AttestationType string
	Transport       []string
	SignCount       uint32
	DeviceName      string
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

type WebAuthnCredentialRepository interface {
	Create(ctx context.Context, c *WebAuthnCredential) error
	FindByID(ctx context.Context, id string) (*WebAuthnCredential, error)
	FindByUser(ctx context.Context, userID string) ([]*WebAuthnCredential, error)
	FindByCredentialID(ctx context.Context, credentialID string) (*WebAuthnCredential, error)
	Update(ctx context.Context, c *WebAuthnCredential) error
	Delete(ctx context.Context, id string) error
}

// MagicLink represents a passwordless magic link token.
type MagicLink struct {
	ID        string
	UserID    string
	TenantID  string
	Token     string // hashed
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

var (
	ErrMagicLinkNotFound = errors.New("magic link not found")
	ErrMagicLinkExpired  = errors.New("magic link expired")
	ErrMagicLinkUsed     = errors.New("magic link already used")
)

type MagicLinkRepository interface {
	Create(ctx context.Context, m *MagicLink) error
	FindByToken(ctx context.Context, token string) (*MagicLink, error)
	MarkUsed(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
}

// PasswordPolicy represents per-tenant password requirements.
type PasswordPolicy struct {
	TenantID            string
	MinLength           int
	RequireUppercase    bool
	RequireLowercase    bool
	RequireNumber       bool
	RequireSpecial      bool
	MaxAgeDays          int // 0 = no expiry
	HistoryCount        int // number of previous passwords to remember
	BreachCheckEnabled  bool
	LockoutThreshold    int // failed attempts before lockout
	LockoutDurationMin  int // minutes
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type PasswordPolicyRepository interface {
	Get(ctx context.Context, tenantID string) (*PasswordPolicy, error)
	Update(ctx context.Context, p *PasswordPolicy) error
}

// FailedLoginAttempt tracks failed login attempts for account lockout.
type FailedLoginAttempt struct {
	ID        string
	Email     string
	TenantID  string
	IP        string
	Count     int
	LockedUntil *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

type FailedLoginAttemptRepository interface {
	Increment(ctx context.Context, email, tenantID, ip string) (*FailedLoginAttempt, error)
	Reset(ctx context.Context, email, tenantID, ip string) error
	Find(ctx context.Context, email, tenantID, ip string) (*FailedLoginAttempt, error)
}

// PasswordResetToken represents a password reset token.
type PasswordResetToken struct {
	ID        string
	UserID    string
	TenantID  string
	Token     string // hashed
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

var (
	ErrPasswordResetTokenNotFound = errors.New("password reset token not found")
	ErrPasswordResetTokenExpired  = errors.New("password reset token expired")
	ErrPasswordResetTokenUsed     = errors.New("password reset token already used")
)

type PasswordResetTokenRepository interface {
	Create(ctx context.Context, t *PasswordResetToken) error
	FindByToken(ctx context.Context, token string) (*PasswordResetToken, error)
	MarkUsed(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
}

// EmailVerificationToken represents an email verification token.
type EmailVerificationToken struct {
	ID        string
	UserID    string
	TenantID  string
	Email     string
	Token     string // hashed
	ExpiresAt time.Time
	VerifiedAt *time.Time
	CreatedAt time.Time
}

var (
	ErrEmailVerificationTokenNotFound = errors.New("email verification token not found")
	ErrEmailVerificationTokenExpired  = errors.New("email verification token expired")
)

type EmailVerificationTokenRepository interface {
	Create(ctx context.Context, t *EmailVerificationToken) error
	FindByToken(ctx context.Context, token string) (*EmailVerificationToken, error)
	MarkVerified(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
}