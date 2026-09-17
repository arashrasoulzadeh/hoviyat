// Command hoviyat runs the Hoviyat backend HTTP server (walking-skeleton
// stage: password auth + JWT + RBAC, single region, Postgres, no cache).
package main

import (
	"log"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/api"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/config"
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
	hasher := service.NewPasswordHasher()
	tokens := service.NewTokenService(cfg.JWTSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	rbac := service.NewRBACService()
	authService := service.NewAuthService(users, tenants, memberships, hasher, tokens)

	authHandler := api.NewAuthHandler(authService)
	userHandler := api.NewUserHandler(users)
	tenantService := service.NewTenantService(tenants)
	tenantHandler := api.NewTenantHandler(tenantService)
	router := api.NewRouter(authHandler, userHandler, tenantHandler, tokens, rbac)

	log.Printf("hoviyat listening on %s", cfg.HTTPAddr)
	if err := router.Run(cfg.HTTPAddr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
