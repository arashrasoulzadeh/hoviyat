package repository

import "time"

// userModel is the GORM-mapped row for users. Kept separate from
// domain.User so persistence concerns (gorm tags) never leak into domain/.
type userModel struct {
	ID           string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Email        string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (userModel) TableName() string { return "users" }

// tenantModel is the GORM-mapped row for tenants.
type tenantModel struct {
	ID        string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Name      string `gorm:"not null"`
	Slug      string `gorm:"uniqueIndex;not null"`
	Status    string `gorm:"not null;default:active"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (tenantModel) TableName() string { return "tenants" }

// membershipModel is the GORM-mapped row linking a user to a tenant with
// tenant-scoped roles. tenant_id is present on the row (and every other
// tenant-scoped table added in later stages) so every query can be scoped
// by tenant at the storage layer (PRD §6).
type membershipModel struct {
	UserID    string `gorm:"primaryKey;type:uuid"`
	TenantID  string `gorm:"primaryKey;type:uuid;index"`
	Roles     string `gorm:"not null;default:''"` // comma-separated; normalized role tables arrive with the ACL/ABAC stage
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (membershipModel) TableName() string { return "memberships" }

type teamModel struct {
	ID        string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	TenantID  string `gorm:"not null;index"`
	Name      string `gorm:"not null"`
	Slug      string `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (teamModel) TableName() string { return "teams" }

type teamMembershipModel struct {
	UserID    string `gorm:"primaryKey;type:uuid"`
	TeamID    string `gorm:"primaryKey;type:uuid;index"`
	Roles     string `gorm:"not null;default:''"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (teamMembershipModel) TableName() string { return "team_memberships" }

type aclModel struct {
	ID           string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	TenantID     string `gorm:"not null;index"`
	SubjectType  string `gorm:"not null;index"`
	SubjectID    string `gorm:"not null;index"`
	ResourceType string `gorm:"not null;index"`
	ResourceID   string `gorm:"not null;index"`
	Permission   string `gorm:"not null"`
	Effect       string `gorm:"not null;default:allow"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (aclModel) TableName() string { return "acl_permissions" }

type rolePermissionModel struct {
	ID         string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	TenantID   string `gorm:"not null;index"`
	RoleName   string `gorm:"not null;index"`
	Permission string `gorm:"not null"`
	CreatedAt  time.Time
}

func (rolePermissionModel) TableName() string { return "role_permissions" }

type permissionModel struct {
	ID          string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	TenantID    string `gorm:"not null;index"`
	Name        string `gorm:"not null;uniqueIndex:idx_tenant_name"`
	Description string
	CreatedAt   time.Time
}

func (permissionModel) TableName() string { return "permissions" }

type policyModel struct {
	ID          string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	TenantID    string `gorm:"not null;index"`
	Name        string `gorm:"not null;uniqueIndex:idx_tenant_name"`
	Description string
	Rego        string `gorm:"type:text;not null"`
	Version     int    `gorm:"not null;default:1"`
	IsActive    bool   `gorm:"not null;default:false"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (policyModel) TableName() string { return "policies" }

type oauth2ProviderModel struct {
	ID               string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	TenantID         string `gorm:"not null;index"`
	Name             string `gorm:"not null"`
	ClientID         string `gorm:"not null"`
	ClientSecret     string `gorm:"not null"`
	AuthURL          string
	TokenURL         string
	UserInfoURL      string
	Scopes           string `gorm:"type:text"` // JSON array
	IssuerURL        string
	ProviderType     string `gorm:"not null"` // google, github, oidc, generic
	Enabled          bool   `gorm:"default:true"`
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (oauth2ProviderModel) TableName() string { return "oauth2_providers" }

type oauth2StateModel struct {
	ID                  string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	State               string `gorm:"uniqueIndex;not null"`
	ProviderID          string `gorm:"not null;index"`
	TenantID            string `gorm:"not null;index"`
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time `gorm:"not null;index"`
	CreatedAt           time.Time
}

func (oauth2StateModel) TableName() string { return "oauth2_states" }

type samlProviderModel struct {
	ID               string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	TenantID         string `gorm:"not null;index"`
	Name             string `gorm:"not null"`
	EntityID         string `gorm:"not null"`
	SSOURL           string `gorm:"not null"`
	SLOURL           string
	X509Cert         string `gorm:"type:text;not null"`
	PrivateKey       string `gorm:"type:text"`
	AttributeMapping string `gorm:"type:text"` // JSON map
	Enabled          bool   `gorm:"default:true"`
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (samlProviderModel) TableName() string { return "saml_providers" }

type mfaMethodModel struct {
	ID          string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID      string `gorm:"not null;index"`
	TenantID    string `gorm:"not null;index"`
	Type        string `gorm:"not null"` // totp, email_otp, sms_otp, webauthn
	Name        string `gorm:"not null"`
	Secret      string `gorm:"type:text"` // encrypted
	BackupCodes string `gorm:"type:text"` // JSON array, encrypted
	IsPrimary   bool   `gorm:"default:false"`
	VerifiedAt  *time.Time
	LastUsedAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (mfaMethodModel) TableName() string { return "mfa_methods" }

type webAuthnCredentialModel struct {
	ID              string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID          string `gorm:"not null;index"`
	TenantID        string `gorm:"not null;index"`
	CredentialID    string `gorm:"uniqueIndex;not null"`
	PublicKey       string `gorm:"type:text;not null"`
	AttestationType string
	Transport       string `gorm:"type:text"` // JSON array
	SignCount       uint32
	DeviceName      string
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

func (webAuthnCredentialModel) TableName() string { return "webauthn_credentials" }

type magicLinkModel struct {
	ID        string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID    string `gorm:"not null;index"`
	TenantID  string `gorm:"not null;index"`
	TokenHash string `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null;index"`
	UsedAt    *time.Time
	CreatedAt time.Time
}

func (magicLinkModel) TableName() string { return "magic_links" }

type passwordPolicyModel struct {
	TenantID           string `gorm:"primaryKey;type:uuid"`
	MinLength          int    `gorm:"default:8"`
	RequireUppercase   bool   `gorm:"default:false"`
	RequireLowercase   bool   `gorm:"default:false"`
	RequireNumber      bool   `gorm:"default:false"`
	RequireSpecial     bool   `gorm:"default:false"`
	MaxAgeDays         int    `gorm:"default:0"`
	HistoryCount       int    `gorm:"default:5"`
	BreachCheckEnabled bool   `gorm:"default:true"`
	LockoutThreshold   int    `gorm:"default:5"`
	LockoutDurationMin int    `gorm:"default:15"`
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func (passwordPolicyModel) TableName() string { return "password_policies" }

type failedLoginAttemptModel struct {
	ID           string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Email        string `gorm:"not null;index:idx_email_tenant_ip"`
	TenantID     string `gorm:"not null;index:idx_email_tenant_ip"`
	IP           string `gorm:"not null;index:idx_email_tenant_ip"`
	Count        int    `gorm:"default:0"`
	LockedUntil  *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (failedLoginAttemptModel) TableName() string { return "failed_login_attempts" }

type passwordResetTokenModel struct {
	ID        string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID    string `gorm:"not null;index"`
	TenantID  string `gorm:"not null;index"`
	TokenHash string `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null;index"`
	UsedAt    *time.Time
	CreatedAt time.Time
}

func (passwordResetTokenModel) TableName() string { return "password_reset_tokens" }

type emailVerificationTokenModel struct {
	ID          string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID      string `gorm:"not null;index"`
	TenantID    string `gorm:"not null;index"`
	Email       string `gorm:"not null"`
	TokenHash   string `gorm:"uniqueIndex;not null"`
	ExpiresAt   time.Time `gorm:"not null;index"`
	VerifiedAt  *time.Time
	CreatedAt   time.Time
}

func (emailVerificationTokenModel) TableName() string { return "email_verification_tokens" }

type oauth2ClientModel struct {
	ID                     string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	TenantID               string `gorm:"not null;index"`
	Name                   string `gorm:"not null"`
	ClientID               string `gorm:"uniqueIndex;not null"`
	ClientSecretHash       string `gorm:"not null"`
	RedirectURIs           string `gorm:"type:text"` // JSON array
	Scopes                 string `gorm:"type:text"` // JSON array
	GrantTypes             string `gorm:"type:text"` // JSON array
	ResponseTypes          string `gorm:"type:text"` // JSON array
	TokenEndpointAuthMethod string `gorm:"default:client_secret_basic"`
	LogoURI                string
	ClientURI              string
	PolicyURI              string
	TOSURI                 string
	JWKSURI                string
	Contacts               string `gorm:"type:text"` // JSON array
	Enabled                bool   `gorm:"default:true"`
	CreatedAt              time.Time
	UpdatedAt              time.Time
	CreatedBy              string
}

func (oauth2ClientModel) TableName() string { return "oauth2_clients" }

type oauth2AuthCodeModel struct {
	ID                string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	ClientID          string `gorm:"not null;index"`
	UserID            string `gorm:"not null;index"`
	TenantID          string `gorm:"not null;index"`
	RedirectURI       string
	Scopes            string `gorm:"type:text"` // JSON array
	CodeChallenge     string
	CodeChallengeMethod string
	Nonce             string
	ExpiresAt         time.Time `gorm:"not null;index"`
	CreatedAt         time.Time
}

func (oauth2AuthCodeModel) TableName() string { return "oauth2_auth_codes" }

type oauth2ConsentModel struct {
	ID        string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID    string `gorm:"not null;index"`
	ClientID  string `gorm:"not null;index"`
	TenantID  string `gorm:"not null;index"`
	Scopes    string `gorm:"type:text"` // JSON array
	ExpiresAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (oauth2ConsentModel) TableName() string { return "oauth2_consents" }

type signingKeyModel struct {
	ID        string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	KeyID     string `gorm:"uniqueIndex;not null"`
	Algorithm string `gorm:"not null;default:RS256"`
	PrivateKey string `gorm:"type:text;not null"` // encrypted
	PublicKey  string `gorm:"type:text;not null"`
	IsActive   bool   `gorm:"default:false"`
	CreatedAt  time.Time
	ExpiresAt  *time.Time
}

func (signingKeyModel) TableName() string { return "signing_keys" }
