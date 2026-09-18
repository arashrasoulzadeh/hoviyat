// Command hoviyat runs the Hoviyat backend HTTP server (walking-skeleton
// stage: password auth + JWT + RBAC, single region, Postgres, no cache).
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/api"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/config"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/middleware"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/repository"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
)

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
	// Note: In production, you'd want to handle Redis connection failure more gracefully
	// and possibly run without cache

	authzService := service.NewAuthorizationService(
		rbac, aclService, abacService, rolePermService, policyService,
		authzCache, memberships, teamMemberships, teams,
	)
	authzHandler := api.NewAuthzHandler(authzService, policyService, aclService, rolePermService, permService)

	// Push invalidation (optional)
	pushInvalidation, err := service.NewPushInvalidation(cfg.RedisURL)
	if err == nil {
		pushInvalidation.RegisterHandler("acl_changed", func(payload string) {
			// Parse payload and invalidate cache
			// Format: tenantID:userID:resourceType:resourceID
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

	router := api.NewRouter(authHandler, userHandler, tenantHandler, teamHandler, authzHandler, tokens, rbac, tenantSignupLimiter)

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
