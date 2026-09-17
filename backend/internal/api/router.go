package api

import (
	"net/http"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/middleware"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

// NewRouter wires the walking-skeleton REST surface: registration/login and
// an authenticated "me" endpoint gated by a basic RBAC permission check.
// gRPC, OAuth2/OIDC/SAML, ABAC, and multi-tenant routes arrive in later
// build stages (docs/TECHNICAL_DESIGN.md).
func NewRouter(auth *AuthHandler, users *UserHandler, tenants *TenantHandler, tokens *service.TokenService, rbac *service.RBACService) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		v1.POST("/auth/register", auth.Register)
		v1.POST("/auth/login", auth.Login)

		me := v1.Group("/users/me")
		me.Use(middleware.RequireAuth(tokens))
		me.GET("", middleware.RequirePermission(rbac, "self:read"), users.Me)

		authed := v1.Group("")
		authed.Use(middleware.RequireAuth(tokens))
		authed.POST("/auth/switch-tenant", auth.SwitchTenant)

		// Tenant provisioning API (PRD §6). Platform-operator-facing;
		// finer-grained RBAC gating arrives with the ACL/ABAC build stage.
		tenantsGroup := authed.Group("/tenants")
		tenantsGroup.POST("", tenants.Create)
		tenantsGroup.POST("/:id/suspend", tenants.Suspend)
		tenantsGroup.POST("/:id/reactivate", tenants.Reactivate)
		tenantsGroup.DELETE("/:id", tenants.Delete)
	}

	return r
}
