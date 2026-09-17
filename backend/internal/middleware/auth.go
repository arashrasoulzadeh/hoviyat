package middleware

import (
	"net/http"
	"strings"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

const (
	ContextUserID   = "userID"
	ContextTenantID = "tenantID"
	ContextRoles    = "roles"
)

// RequireAuth validates the bearer JWT and stores the caller's identity and
// roles in the request context for downstream handlers/middleware.
func RequireAuth(tokens *service.TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": gin.H{"code": "missing_token", "message": "authorization bearer token is required"}})
			return
		}
		claims, err := tokens.Parse(strings.TrimPrefix(header, prefix))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": gin.H{"code": "invalid_token", "message": "the provided token is invalid or expired"}})
			return
		}
		c.Set(ContextUserID, claims.UserID)
		c.Set(ContextTenantID, claims.TenantID)
		c.Set(ContextRoles, claims.Roles)
		c.Next()
	}
}

// RequirePermission enforces a coarse-grained RBAC check. Must run after
// RequireAuth.
func RequirePermission(rbac *service.RBACService, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, _ := c.Get(ContextRoles)
		roleList, _ := roles.([]string)
		if !rbac.Allow(roleList, permission) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": gin.H{"code": "forbidden", "message": "you do not have permission to perform this action"}})
			return
		}
		c.Next()
	}
}
