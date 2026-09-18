// Command hoviyat runs the Hoviyat backend HTTP server (walking-skeleton
// stage: password auth + JWT + RBAC, single region, Postgres, no cache).
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/api"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/config"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/middleware"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/repository"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
)

type mockEmailSender struct{}

func (m *mockEmailSender) SendMagicLink(ctx context.Context, email, link string) error {
	log.Printf("MOCK EMAIL: Magic link sent to %s: %s", email, link)
	return nil
}

func (m *mockEmailSender) SendPasswordReset(ctx context.Context, email, link string) error {
	log.Printf("MOCK EMAIL: Password reset sent to %s: %s", email, link)
	return nil
}

func (m *mockEmailSender) SendEmailVerification(ctx context.Context, email, link string) error {
	log.Printf("MOCK EMAIL: Email verification sent to %s: %s", email, link)
	return nil
}

func (m *mockEmailSender) SendOTP(ctx context.Context, email, otp string) error {
	log.Printf("MOCK EMAIL: OTP sent to %s: %s", email, otp)
	return nil
}

func (m *mockEmailSender) SendSMS(ctx context.Context, phone, otp string) error {
	log.Printf("MOCK SMS: OTP sent to %s: %s", phone, otp)
	return nil
}

func main() {
	cfg := config.Load()

	db, err := repository.NewDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect to database: %v", err)
	}
	if err := repository.AutoMigrate(db); err != nil {
		log.Fatalf("run migrations: %v", err)
	}

	users := repository.NewUserRepository(db)
	tenants := repository.NewTenantRepository(db)
	memberships := repository.NewMembershipRepository(db)
	teams := repository.NewTeamRepository(db)
	teamMemberships := repository.NewTeamMembershipRepository(db)
	aclRepo := repository.NewACLRepository(db)
	rolePermRepo := repository.NewRolePermissionRepository(db)
	permRepo := repository.NewPermissionRepository(db)
	policyRepo := repository.NewPolicyRepository(db)

	// Auth extension repositories
	oauth2ProviderRepo := repository.NewOAuth2ProviderRepository(db)
	oauth2StateRepo := repository.NewOAuth2StateRepository(db)
	samlProviderRepo := repository.NewSAMLProviderRepository(db)
	mfaMethodRepo := repository.NewMFAMethodRepository(db)
	webAuthnCredRepo := repository.NewWebAuthnCredentialRepository(db)
	magicLinkRepo := repository.NewMagicLinkRepository(db)
	_ = repository.NewPasswordPolicyRepository(db)
	_ = repository.NewFailedLoginAttemptRepository(db)
	_ = repository.NewPasswordResetTokenRepository(db)
	_ = repository.NewEmailVerificationTokenRepository(db)

	// IdP repositories
	oauth2ClientRepo := repository.NewOAuth2ClientRepository(db)
	oauth2AuthCodeRepo := repository.NewOAuth2AuthCodeRepository(db)
	oauth2ConsentRepo := repository.NewOAuth2ConsentRepository(db)
	signingKeyRepo := repository.NewSigningKeyRepository(db)

	hasher := service.NewPasswordHasher()
	tokens := service.NewTokenService(cfg.JWTSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	rbac := service.NewRBACService()
	authService := service.NewAuthService(users, tenants, memberships, teamMemberships, teams, hasher, tokens)

	authHandler := api.NewAuthHandler(authService)
	userHandler := api.NewUserHandler(users, memberships, teamMemberships, teams)
	tenantService := service.NewTenantService(tenants)
	riskScorer := service.NewRiskScorer()
	tenantHandler := api.NewTenantHandler(tenantService, riskScorer)
	teamService := service.NewTeamService(teams)
	teamMembershipService := service.NewTeamMembershipService(teamMemberships, teams)
	teamHandler := api.NewTeamHandler(teamService, teamMembershipService)

	aclService := service.NewACLService(aclRepo)
	rolePermService := service.NewRolePermissionService(rolePermRepo)
	permService := service.NewPermissionService(permRepo)
	policyService := service.NewPolicyService(policyRepo)
	abacService := service.NewABACService()

	authzCache, err := service.NewAuthzCache(cfg.RedisURL, cfg.AuthzCacheTTL)
	if err != nil {
		log.Printf("warning: failed to connect to Redis, running without cache: %v", err)
	}

	authzService := service.NewAuthorizationService(
		rbac, aclService, abacService, rolePermService, policyService,
		authzCache, memberships, teamMemberships, teams,
	)
	authzHandler := api.NewAuthzHandler(authzService, policyService, aclService, rolePermService, permService)

	// OAuth2 service (relying party)
	oauth2Service := service.NewOAuth2Service(
		oauth2ProviderRepo, oauth2StateRepo, users, memberships,
		teams, teamMemberships, hasher, tokens,
	)
	oauth2Handler := api.NewOAuth2Handler(oauth2Service, tokens)

	// SAML service
	samlService := service.NewSAMLService(
		samlProviderRepo, users, memberships,
		teams, teamMemberships, hasher, tokens,
	)
	samlHandler := api.NewSAMLHandler(samlService, tokens)

	// MFA service
	webAuthn := &webauthn.WebAuthn{}
	mfaService := service.NewMFAService(mfaMethodRepo, webAuthnCredRepo, users, webAuthn)
	mfaHandler := api.NewMFAHandler(mfaService, tokens)

	// Passwordless service
	emailSender := &mockEmailSender{}
	passwordlessService := service.NewPasswordlessService(
		magicLinkRepo, users, memberships,
		teams, teamMemberships, tokens, emailSender,
	)
	passwordlessHandler := api.NewPasswordlessHandler(passwordlessService, tokens)

	// IdP services (Hoviyat as Identity Provider)
	clientService := service.NewOAuth2ClientService(
		oauth2ClientRepo, oauth2AuthCodeRepo, oauth2ConsentRepo, signingKeyRepo,
	)
	jwksService := service.NewJWKSService(signingKeyRepo)
	if err := jwksService.Initialize(context.Background()); err != nil {
		log.Printf("warning: failed to initialize JWKS: %v", err)
	}
	// Start key rotation every 24 hours
	go jwksService.StartKeyRotation(context.Background(), 24*time.Hour)

	idpHandler := api.NewIdPHandler(clientService, jwksService, tokens)

	// Push invalidation (optional)
	pushInvalidation, err := service.NewPushInvalidation(cfg.RedisURL)
	if err == nil {
		pushInvalidation.RegisterHandler("acl_changed", func(payload string) {
			log.Printf("Invalidation event: acl_changed %s", payload)
		})
		pushInvalidation.RegisterHandler("policy_changed", func(payload string) {
			log.Printf("Invalidation event: policy_changed %s", payload)
		})
		go func() {
			ctx := context.Background()
			if err := pushInvalidation.Start(ctx); err != nil {
				log.Printf("push invalidation error: %v", err)
			}
		}()
	}

	tenantSignupLimiter := middleware.NewTenantSignupRateLimiter(cfg.TenantSignupRateLimit, cfg.TenantSignupWindow)

	router := api.NewRouter(
		authHandler, userHandler, tenantHandler, teamHandler, authzHandler,
		oauth2Handler, samlHandler, mfaHandler, passwordlessHandler, idpHandler,
		tokens, rbac, tenantSignupLimiter,
	)

	// Graceful shutdown
	go func() {
		log.Printf("hoviyat listening on %s", cfg.HTTPAddr)
		if err := router.Run(cfg.HTTPAddr); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down...")

	if authzCache != nil {
		authzCache.Close()
	}
	if pushInvalidation != nil {
		pushInvalidation.Close()
	}
}