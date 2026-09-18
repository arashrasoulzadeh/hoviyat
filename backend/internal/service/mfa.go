package service

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

var (
	ErrMFAMethodNotFound     = errors.New("mfa method not found")
	ErrMFAAlreadyEnrolled    = errors.New("mfa method already enrolled")
	ErrMFAVerificationFailed = errors.New("mfa verification failed")
	ErrInvalidTOTPCode       = errors.New("invalid totp code")
	ErrNoPrimaryMFA          = errors.New("no primary mfa method")
)

type MFAService struct {
	methods     domain.MFAMethodRepository
	credentials domain.WebAuthnCredentialRepository
	users       domain.UserRepository
}

func NewMFAService(
	methods domain.MFAMethodRepository,
	credentials domain.WebAuthnCredentialRepository,
	users domain.UserRepository,
	webAuthn interface{}, // placeholder for future WebAuthn integration
) *MFAService {
	return &MFAService{
		methods:     methods,
		credentials: credentials,
		users:       users,
	}
}

func (s *MFAService) EnrollTOTP(ctx context.Context, userID, tenantID, name string) (*domain.MFAMethod, string, string, []string, error) {
	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Hoviyat",
		AccountName: userID,
		SecretSize:  32,
	})
	if err != nil {
		return nil, "", "", nil, err
	}

	// Generate backup codes
	backupCodes := generateBackupCodes(10)

	method := &domain.MFAMethod{
		UserID:      userID,
		TenantID:    tenantID,
		Type:        "totp",
		Name:        name,
		Secret:      key.Secret(),
		BackupCodes: backupCodes,
		IsPrimary:   true,
	}
	if err := s.methods.Create(ctx, method); err != nil {
		return nil, "", "", nil, err
	}

	// Return secret for QR code generation, backup codes
	qrCode := key.URL()
	return method, key.Secret(), qrCode, backupCodes, nil
}

func (s *MFAService) VerifyTOTP(ctx context.Context, userID, code string) error {
	method, err := s.methods.FindPrimaryByUser(ctx, userID)
	if err != nil {
		return ErrMFAMethodNotFound
	}
	if method.Type != "totp" {
		return ErrMFAVerificationFailed
	}

	valid := totp.Validate(code, method.Secret)
	if !valid {
		return ErrInvalidTOTPCode
	}

	now := time.Now()
	method.LastUsedAt = &now
	return s.methods.Update(ctx, method)
}

func (s *MFAService) VerifyBackupCode(ctx context.Context, userID, code string) error {
	methods, err := s.methods.FindByUser(ctx, userID)
	if err != nil {
		return ErrMFAMethodNotFound
	}

	for _, method := range methods {
		if method.Type == "totp" {
			for i, bc := range method.BackupCodes {
				if bc == code {
					// Remove used backup code
					method.BackupCodes = append(method.BackupCodes[:i], method.BackupCodes[i+1:]...)
					now := time.Now()
					method.LastUsedAt = &now
					return s.methods.Update(ctx, method)
				}
			}
		}
	}
	return ErrInvalidTOTPCode
}

func (s *MFAService) EnrollWebAuthn(ctx context.Context, userID, tenantID, deviceName string) (interface{}, interface{}, error) {
	// Placeholder for WebAuthn enrollment
	// TODO: Implement with go-webauthn/webauthn v0.18+ API
	return nil, nil, errors.New("webauthn enrollment not yet implemented")
}

func (s *MFAService) CompleteWebAuthnEnrollment(ctx context.Context, userID, tenantID, deviceName string, sessionData interface{}, response interface{}) (*domain.WebAuthnCredential, error) {
	// Placeholder for WebAuthn enrollment completion
	return nil, errors.New("webauthn enrollment not yet implemented")
}

func (s *MFAService) BeginWebAuthnAuthentication(ctx context.Context, userID string) (interface{}, interface{}, error) {
	// Placeholder for WebAuthn authentication
	return nil, nil, errors.New("webauthn authentication not yet implemented")
}

func (s *MFAService) CompleteWebAuthnAuthentication(ctx context.Context, userID string, sessionData interface{}, response interface{}) error {
	// Placeholder for WebAuthn authentication completion
	return errors.New("webauthn authentication not yet implemented")
}

func (s *MFAService) ListMethods(ctx context.Context, userID string) ([]*domain.MFAMethod, error) {
	return s.methods.FindByUser(ctx, userID)
}

func (s *MFAService) RemoveMethod(ctx context.Context, userID, methodID string) error {
	method, err := s.methods.FindByID(ctx, methodID)
	if err != nil {
		return err
	}
	if method.UserID != userID {
		return ErrMFAMethodNotFound
	}
	return s.methods.Delete(ctx, methodID)
}

func (s *MFAService) SetPrimaryMethod(ctx context.Context, userID, methodID string) error {
	methods, err := s.methods.FindByUser(ctx, userID)
	if err != nil {
		return err
	}

	for _, m := range methods {
		m.IsPrimary = (m.ID == methodID)
		if err := s.methods.Update(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

func generateBackupCodes(count int) []string {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		b := make([]byte, 6)
		rand.Read(b)
		codes[i] = strings.ToUpper(base32.StdEncoding.EncodeToString(b))[:8]
	}
	return codes
}

func ptr[T any](v T) *T {
	return &v
}