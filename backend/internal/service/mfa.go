package service

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/go-webauthn/webauthn/webauthn"
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
	methods       domain.MFAMethodRepository
	credentials   domain.WebAuthnCredentialRepository
	users         domain.UserRepository
	webAuthn      *webauthn.WebAuthn
}

func NewMFAService(
	methods domain.MFAMethodRepository,
	credentials domain.WebAuthnCredentialRepository,
	users domain.UserRepository,
	webAuthn *webauthn.WebAuthn,
) *MFAService {
	return &MFAService{
		methods:     methods,
		credentials: credentials,
		users:       users,
		webAuthn:    webAuthn,
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

func (s *MFAService) EnrollWebAuthn(ctx context.Context, userID, tenantID, deviceName string) (*webauthn.CredentialCreation, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Create webauthn user
	webAuthnUser := &webauthnUserAdapter{user: user}

	options, sessionData, err := s.webAuthn.BeginRegistration(webAuthnUser)
	if err != nil {
		return nil, err
	}

	// Store session data temporarily (in production, use Redis with TTL)
	// For now, we'll return the options and the caller must store sessionData

	return options, sessionData, nil
}

func (s *MFAService) CompleteWebAuthnEnrollment(ctx context.Context, userID, tenantID, deviceName string, sessionData webauthn.SessionData, response *webauthn.CredentialCreationResponse) (*domain.WebAuthnCredential, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	webAuthnUser := &webauthnUserAdapter{user: user}

	credential, err := s.webAuthn.CreateCredential(webAuthnUser, sessionData, response)
	if err != nil {
		return nil, err
	}

	webAuthnCred := &domain.WebAuthnCredential{
		UserID:          userID,
		TenantID:        tenantID,
		CredentialID:    credential.ID,
		PublicKey:       base64.StdEncoding.EncodeToString(credential.PublicKey),
		AttestationType: credential.AttestationType,
		Transport:       credential.Transport,
		SignCount:       credential.Authenticator.SignCount,
		DeviceName:      deviceName,
	}

	if err := s.credentials.Create(ctx, webAuthnCred); err != nil {
		return nil, err
	}

	// Also create MFA method entry
	method := &domain.MFAMethod{
		UserID:    userID,
		TenantID:  tenantID,
		Type:      "webauthn",
		Name:      deviceName,
		Secret:    credential.ID,
		IsPrimary: true,
	}
	if err := s.methods.Create(ctx, method); err != nil {
		return nil, err
	}

	return webAuthnCred, nil
}

func (s *MFAService) BeginWebAuthnAuthentication(ctx context.Context, userID string) (*webauthn.CredentialAssertion, webauthn.SessionData, error) {
	credentials, err := s.credentials.FindByUser(ctx, userID)
	if err != nil {
		return nil, webauthn.SessionData{}, err
	}

	if len(credentials) == 0 {
		return nil, webauthn.SessionData{}, ErrMFAMethodNotFound
	}

	webAuthnUser := &webauthnUserAdapter{userID: userID, credentials: credentials}
	options, sessionData, err := s.webAuthn.BeginLogin(webAuthnUser)
	if err != nil {
		return nil, webauthn.SessionData{}, err
	}

	return options, sessionData, nil
}

func (s *MFAService) CompleteWebAuthnAuthentication(ctx context.Context, userID string, sessionData webauthn.SessionData, response *webauthn.CredentialAssertionResponse) error {
	credentials, err := s.credentials.FindByUser(ctx, userID)
	if err != nil {
		return err
	}

	webAuthnUser := &webauthnUserAdapter{userID: userID, credentials: credentials}

	credential, err := s.webAuthn.ValidateLogin(webAuthnUser, sessionData, response)
	if err != nil {
		return err
	}

	// Update sign count
	for _, c := range credentials {
		if c.CredentialID == credential.ID {
			c.SignCount = credential.Authenticator.SignCount
			c.LastUsedAt = ptr(time.Now())
			s.credentials.Update(ctx, c)
			break
		}
	}

	// Update MFA method last used
	methods, _ := s.methods.FindByUser(ctx, userID)
	for _, m := range methods {
		if m.Type == "webauthn" && m.Secret == credential.ID {
			now := time.Now()
			m.LastUsedAt = &now
			s.methods.Update(ctx, m)
			break
		}
	}

	return nil
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

// webauthnUserAdapter implements webauthn.User
type webauthnUserAdapter struct {
	userID      string
	user        *domain.User
	credentials []*domain.WebAuthnCredential
}

func (u *webauthnUserAdapter) WebAuthnID() []byte {
	return []byte(u.userID)
}

func (u *webauthnUserAdapter) WebAuthnName() string {
	if u.user != nil {
		return u.user.Email
	}
	return u.userID
}

func (u *webauthnUserAdapter) WebAuthnDisplayName() string {
	if u.user != nil {
		return u.user.Email
	}
	return u.userID
}

func (u *webauthnUserAdapter) WebAuthnIcon() string {
	return ""
}

func (u *webauthnUserAdapter) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, len(u.credentials))
	for i, c := range u.credentials {
		pubKey, _ := base64.StdEncoding.DecodeString(c.PublicKey)
		creds[i] = webauthn.Credential{
			ID:              []byte(c.CredentialID),
			PublicKey:       pubKey,
			AttestationType: c.AttestationType,
			Transport:       c.Transport,
			Flags: webauthn.CredentialFlags{
				UserVerificationRequirement: webauthn.VerificationPreferred,
			},
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
			},
		}
	}
	return creds
}