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
