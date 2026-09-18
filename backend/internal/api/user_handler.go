package api

import (
	"errors"
	"net/http"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/middleware"
	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	users             domain.UserRepository
	memberships       domain.MembershipRepository
	teamMemberships   domain.TeamMembershipRepository
	teams             domain.TeamRepository
}

func NewUserHandler(users domain.UserRepository, memberships domain.MembershipRepository, teamMemberships domain.TeamMembershipRepository, teams domain.TeamRepository) *UserHandler {
	return &UserHandler{users: users, memberships: memberships, teamMemberships: teamMemberships, teams: teams}
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

// ListMemberships returns the authenticated user's tenant memberships.
func (h *UserHandler) ListMemberships(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	id, _ := userID.(string)
	memberships, err := h.memberships.ListByUser(c.Request.Context(), id)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list memberships")
		return
	}
	resp := make([]gin.H, 0, len(memberships))
	for _, m := range memberships {
		resp = append(resp, gin.H{
			"tenant_id": m.TenantID,
			"roles":     m.Roles,
		})
	}
	c.JSON(http.StatusOK, resp)
}

// ListTeamMemberships returns the authenticated user's team memberships.
func (h *UserHandler) ListTeamMemberships(c *gin.Context) {
	userID, _ := c.Get(middleware.ContextUserID)
	id, _ := userID.(string)
	tms, err := h.teamMemberships.ListByUser(c.Request.Context(), id)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list team memberships")
		return
	}
	resp := make([]gin.H, 0, len(tms))
	for _, tm := range tms {
		team, err := h.teams.FindByID(c.Request.Context(), tm.TeamID)
		if err != nil {
			continue
		}
		resp = append(resp, gin.H{
			"team_id":   tm.TeamID,
			"team_name": team.Name,
			"tenant_id": team.TenantID,
			"roles":     tm.Roles,
		})
	}
	c.JSON(http.StatusOK, resp)
}
