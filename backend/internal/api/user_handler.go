package api

import (
	"errors"
	"net/http"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/middleware"
	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	users domain.UserRepository
}

func NewUserHandler(users domain.UserRepository) *UserHandler {
	return &UserHandler{users: users}
}

// Me returns the authenticated caller's own profile (permission: self:read).
func (h *UserHandler) Me(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	id, _ := userID.(string)
	user, err := h.users.FindByID(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			writeError(c, http.StatusNotFound, "user_not_found", "user not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to load user")
		return
	}
	tenantID, _ := c.Get(middleware.ContextTenantID)
	roles, _ := c.Get(middleware.ContextRoles)
	c.JSON(http.StatusOK, gin.H{
		"id":        user.ID,
		"email":     user.Email,
		"tenant_id": tenantID,
		"roles":     roles,
	})
}
