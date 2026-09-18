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
func NewRouter(
	auth *AuthHandler,
	users *UserHandler,
	tenants *TenantHandler,
	teams *TeamHandler,
	authz *AuthzHandler,
	oauth2 *OAuth2Handler,
	saml *SAMLHandler,
	mfa *MFAHandler,
	passwordless *PasswordlessHandler,
	tokens *service.TokenService,
	rbac *service.RBACService,
	tenantSignupLimiter *middleware.TenantSignupRateLimiter,
) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		v1.POST("/auth/register", auth.Register)
		v1.POST("/auth/login", auth.Login)

		// Public tenant signup with rate limiting (PRD §7, §9)
		v1.POST("/tenants", tenantSignupLimiter.Middleware(), tenants.Create)

		// OAuth2/OIDC (PRD §6)
		oauth2Group := v1.Group("/oauth2")
		oauth2Group.POST("/:tenantId/providers", oauth2.RegisterProvider)
		oauth2Group.GET("/:tenantId/providers", oauth2.ListProviders)
		oauth2Group.GET("/:tenantId/providers/:id", oauth2.GetProvider)
		oauth2Group.DELETE("/:tenantId/providers/:id", oauth2.DeleteProvider)
		oauth2Group.POST("/:tenantId/auth-url", oauth2.GetAuthURL)
		oauth2Group.POST("/callback", oauth2.HandleCallback)
		oauth2Group.GET("/callback", oauth2.RedirectCallback)

		// SAML 2.0 (PRD §6)
		samlGroup := v1.Group("/saml")
		samlGroup.POST("/:tenantId/providers", saml.RegisterProvider)
		samlGroup.GET("/:tenantId/providers", saml.ListProviders)
		samlGroup.GET("/:tenantId/providers/:id", saml.GetProvider)
		samlGroup.DELETE("/:tenantId/providers/:id", saml.DeleteProvider)
		samlGroup.GET("/providers/:providerId/sso", saml.InitiateSSO)
		samlGroup.POST("/providers/:providerId/acs", saml.ACS)
		samlGroup.GET("/providers/:providerId/slo", saml.SLO)
		samlGroup.GET("/providers/:providerId/metadata", saml.Metadata)

		me := v1.Group("/users/me")
		me.Use(middleware.RequireAuth(tokens))
		me.GET("", middleware.RequirePermission(rbac, "self:read"), users.Me)
		me.GET("/memberships", middleware.RequirePermission(rbac, "self:read"), users.ListMemberships)
		me.GET("/team-memberships", middleware.RequirePermission(rbac, "self:read"), users.ListTeamMemberships)

		authed := v1.Group("")
		authed.Use(middleware.RequireAuth(tokens))
		authed.POST("/auth/switch-tenant", auth.SwitchTenant)
		authed.POST("/auth/leave-tenant", auth.LeaveTenant)

		// MFA (PRD §6)
		mfaGroup := authed.Group("/mfa")
		mfaGroup.POST("/totp", mfa.EnrollTOTP)
		mfaGroup.POST("/totp/verify", mfa.VerifyTOTP)
		mfaGroup.POST("/backup-code/verify", mfa.VerifyBackupCode)
		mfaGroup.GET("", mfa.ListMethods)
		mfaGroup.DELETE("", mfa.RemoveMethod)
		mfaGroup.PATCH("/primary", mfa.SetPrimary)
		mfaGroup.POST("/webauthn/begin", mfa.BeginWebAuthnEnrollment)
		mfaGroup.POST("/webauthn/complete", mfa.CompleteWebAuthnEnrollment)
		mfaGroup.POST("/webauthn/auth/begin", mfa.BeginWebAuthnAuthentication)
		mfaGroup.POST("/webauthn/auth/complete", mfa.CompleteWebAuthnAuthentication)

		// Passwordless (PRD §6)
		passwordlessGroup := authed.Group("/passwordless")
		passwordlessGroup.POST("/magic-link", passwordless.SendMagicLink)
		passwordlessGroup.POST("/magic-link/verify", passwordless.VerifyMagicLink)
		passwordlessGroup.POST("/password-reset/request", passwordless.RequestPasswordReset)
		passwordlessGroup.POST("/password-reset/confirm", passwordless.ResetPassword)
		passwordlessGroup.POST("/email/verify", passwordless.VerifyEmail)

		// Password policy (tenant admin)
		passwordPolicyGroup := authed.Group("/password-policy")
		passwordPolicyGroup.GET("/:tenantId", passwordless.GetPasswordPolicy)
		passwordPolicyGroup.PATCH("/:tenantId", passwordless.UpdatePasswordPolicy)

		// Authorization API (PRD §6, §70-§76)
		authzGroup := authed.Group("/authz")
		authzGroup.POST("/check", authz.Check)
		authzGroup.POST("/dry-run", authz.DryRun)

		// ACL management
		aclGroup := authzGroup.Group("/acl")
		aclGroup.POST("/:tenantId", authz.GrantACL)
		aclGroup.DELETE("/:tenantId", authz.RevokeACL)
		aclGroup.GET("/:tenantId/by-subject", authz.ListACLBySubject)
		aclGroup.GET("/:tenantId/by-resource", authz.ListACLByResource)

		// Role-Permission management
		rolePermGroup := authzGroup.Group("/roles/:roleName/permissions")
		rolePermGroup.POST("/:tenantId", authz.GrantRolePermission)
		rolePermGroup.DELETE("/:tenantId", authz.RevokeRolePermission)
		rolePermGroup.DELETE("/:tenantId/all", authz.RevokeAllRolePermissions)
		rolePermGroup.GET("/:tenantId", authz.ListRolePermissions)

		// Permission definitions
		permGroup := authzGroup.Group("/permissions")
		permGroup.POST("/:tenantId", authz.CreatePermission)
		permGroup.GET("/:tenantId", authz.ListPermissions)
		permGroup.GET("/:tenantId/:id", authz.GetPermission)
		permGroup.DELETE("/:tenantId/:id", authz.DeletePermission)

		// Policy management (OPA/Rego)
		policyGroup := authzGroup.Group("/policies")
		policyGroup.POST("/:tenantId", authz.CreatePolicy)
		policyGroup.GET("/:tenantId", authz.ListPolicies)
		policyGroup.GET("/:tenantId/:id", authz.GetPolicy)
		policyGroup.POST("/:tenantId/:id/activate", authz.ActivatePolicy)
		policyGroup.POST("/:tenantId/:id/deactivate", authz.DeactivatePolicy)
		policyGroup.DELETE("/:tenantId/:id", authz.DeletePolicy)

		// Tenant provisioning API (PRD §6). Platform-operator-facing;
		// finer-grained RBAC gating arrives with the ACL/ABAC build stage.
		tenantsGroup := authed.Group("/tenants")
		tenantsGroup.POST("/:id/suspend", tenants.Suspend)
		tenantsGroup.POST("/:id/reactivate", tenants.Reactivate)
		tenantsGroup.POST("/:id/activate", tenants.Activate)
		tenantsGroup.DELETE("/:id", tenants.Delete)

		// Team management (nested under tenant, PRD §9)
		teamsGroup := authed.Group("/teams")
		teamsGroup.POST("", teams.Create)
		teamsGroup.GET("", teams.List)
		teamsGroup.GET("/:id", teams.Get)
		teamsGroup.POST("/:id/members", teams.AddMember)
		teamsGroup.GET("/:id/members", teams.ListMembers)
		teamsGroup.GET("/:id/members/:userId", teams.GetMember)
		teamsGroup.PATCH("/:id/members/:userId", teams.UpdateMember)
		teamsGroup.DELETE("/:id/members/:userId", teams.RemoveMember)
	}

	return r
}
