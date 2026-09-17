package domain

import (
	"context"
	"errors"
	"time"
)

// User is the core identity entity. A user account is tenant-agnostic:
// roles/permissions live on Membership, scoped per tenant (see
// membership.go), so a single account can belong to many tenants with
// different roles in each — analogous to Slack/GitHub org membership
// (PRD §6 "Multi-tenancy").
type User struct {
	ID           string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// UserRepository is the persistence boundary for users. Concrete
// implementations live in internal/repository and are backed by GORM.
type UserRepository interface {
	Create(ctx context.Context, user *User) error
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByID(ctx context.Context, id string) (*User, error)
}
