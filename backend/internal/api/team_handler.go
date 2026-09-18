package api

import (
	"errors"
	"net/http"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

type TeamHandler struct {
	teams              *service.TeamService
	teamMemberships    *service.TeamMembershipService
}

func NewTeamHandler(teams *service.TeamService, teamMemberships *service.TeamMembershipService) *TeamHandler {
	return &TeamHandler{teams: teams, teamMemberships: teamMemberships}
}

type createTeamRequest struct {
	Name string `json:"name" binding:"required"`
	Slug string `json:"slug" binding:"required"`
}

type addTeamMemberRequest struct {
	UserID string   `json:"user_id" binding:"required"`
	Roles  []string `json:"roles"`
}

type updateTeamMemberRequest struct {
	Roles []string `json:"roles"`
}

func toTeamResponse(team *domain.Team) gin.H {
	return gin.H{
		"id":         team.ID,
		"tenant_id":  team.TenantID,
		"name":       team.Name,
		"slug":       team.Slug,
		"created_at": team.CreatedAt,
		"updated_at": team.UpdatedAt,
	}
}

func toTeamMembershipResponse(tm *domain.TeamMembership) gin.H {
	return gin.H{
		"user_id":    tm.UserID,
		"team_id":    tm.TeamID,
		"roles":      tm.Roles,
		"created_at": tm.CreatedAt,
		"updated_at": tm.UpdatedAt,
	}
}

func (h *TeamHandler) Create(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		writeError(c, http.StatusBadRequest, "invalid_request", "tenant_id query parameter is required")
		return
	}
	var req createTeamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	team, err := h.teams.Create(c.Request.Context(), tenantID, req.Name, req.Slug)
	if err != nil {
		if errors.Is(err, domain.ErrTeamAlreadyExists) {
			writeError(c, http.StatusConflict, "team_exists", "a team with this slug already exists in this tenant")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to create team")
		return
	}
	c.JSON(http.StatusCreated, toTeamResponse(team))
}

func (h *TeamHandler) List(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		writeError(c, http.StatusBadRequest, "invalid_request", "tenant_id query parameter is required")
		return
	}
	teams, err := h.teams.ListByTenant(c.Request.Context(), tenantID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list teams")
		return
	}
	resp := make([]gin.H, 0, len(teams))
	for _, t := range teams {
		resp = append(resp, toTeamResponse(t))
	}
	c.JSON(http.StatusOK, resp)
}

func (h *TeamHandler) Get(c *gin.Context) {
	id := c.Param("id")
	team, err := h.teams.GetByID(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrTeamNotFound) {
			writeError(c, http.StatusNotFound, "team_not_found", "team not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to get team")
		return
	}
	c.JSON(http.StatusOK, toTeamResponse(team))
}

func (h *TeamHandler) AddMember(c *gin.Context) {
	teamID := c.Param("id")
	var req addTeamMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tm, err := h.teamMemberships.AddMember(c.Request.Context(), req.UserID, teamID, req.Roles)
	if err != nil {
		if errors.Is(err, domain.ErrTeamMembershipAlreadyExists) {
			writeError(c, http.StatusConflict, "member_exists", "user is already a member of this team")
			return
		}
		if errors.Is(err, domain.ErrTeamNotFound) {
			writeError(c, http.StatusNotFound, "team_not_found", "team not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to add team member")
		return
	}
	c.JSON(http.StatusCreated, toTeamMembershipResponse(tm))
}

func (h *TeamHandler) ListMembers(c *gin.Context) {
	teamID := c.Param("id")
	members, err := h.teamMemberships.ListTeamMembers(c.Request.Context(), teamID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list team members")
		return
	}
	resp := make([]gin.H, 0, len(members))
	for _, m := range members {
		resp = append(resp, toTeamMembershipResponse(m))
	}
	c.JSON(http.StatusOK, resp)
}

func (h *TeamHandler) GetMember(c *gin.Context) {
	teamID := c.Param("id")
	userID := c.Param("userId")
	tm, err := h.teamMemberships.GetMembership(c.Request.Context(), userID, teamID)
	if err != nil {
		if errors.Is(err, domain.ErrTeamMembershipNotFound) {
			writeError(c, http.StatusNotFound, "member_not_found", "user is not a member of this team")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to get team member")
		return
	}
	c.JSON(http.StatusOK, toTeamMembershipResponse(tm))
}

func (h *TeamHandler) UpdateMember(c *gin.Context) {
	teamID := c.Param("id")
	userID := c.Param("userId")
	var req updateTeamMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.teamMemberships.UpdateRoles(c.Request.Context(), userID, teamID, req.Roles); err != nil {
		if errors.Is(err, domain.ErrTeamMembershipNotFound) {
			writeError(c, http.StatusNotFound, "member_not_found", "user is not a member of this team")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to update team member")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TeamHandler) RemoveMember(c *gin.Context) {
	teamID := c.Param("id")
	userID := c.Param("userId")
	if err := h.teamMemberships.RemoveMember(c.Request.Context(), userID, teamID); err != nil {
		if errors.Is(err, domain.ErrTeamMembershipNotFound) {
			writeError(c, http.StatusNotFound, "member_not_found", "user is not a member of this team")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to remove team member")
		return
	}
	c.Status(http.StatusNoContent)
}