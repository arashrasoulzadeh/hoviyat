package api

import (
	"errors"
	"net/http"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
	"github.com/gin-gonic/gin"
)

type AuthzHandler struct {
	authz       *service.AuthorizationService
	policy      *service.PolicyService
	acl         *service.ACLService
	rolePerms   *service.RolePermissionService
	perms       *service.PermissionService
}

func NewAuthzHandler(authz *service.AuthorizationService, policy *service.PolicyService, acl *service.ACLService, rolePerms *service.RolePermissionService, perms *service.PermissionService) *AuthzHandler {
	return &AuthzHandler{authz: authz, policy: policy, acl: acl, rolePerms: rolePerms, perms: perms}
}

type authzCheckRequest struct {
	UserID       string                 `json:"user_id" binding:"required"`
	TenantID     string                 `json:"tenant_id" binding:"required"`
	ResourceType string                 `json:"resource_type" binding:"required"`
	ResourceID   string                 `json:"resource_id" binding:"required"`
	Action       string                 `json:"action" binding:"required"`
	Context      map[string]interface{} `json:"context"`
}

type authzCheckResponse struct {
	Allowed    bool   `json:"allowed"`
	Reason     string `json:"reason"`
	MatchedBy  string `json:"matched_by"`
}

func (h *AuthzHandler) Check(c *gin.Context) {
	var req authzCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	result, err := h.authz.Check(c.Request.Context(), service.AuthzRequest{
		UserID:       req.UserID,
		TenantID:     req.TenantID,
		ResourceType: req.ResourceType,
		ResourceID:   req.ResourceID,
		Action:       req.Action,
		Context:      req.Context,
	})
	if err != nil {
		if errors.Is(err, domain.ErrMembershipNotFound) || errors.Is(err, domain.ErrTenantNotFound) {
			writeError(c, http.StatusNotFound, "not_found", err.Error())
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "authorization check failed")
		return
	}

	c.JSON(http.StatusOK, authzCheckResponse{
		Allowed:   result.Allowed,
		Reason:    result.Reason,
		MatchedBy: result.MatchedBy,
	})
}

type authzDryRunRequest struct {
	UserID       string                 `json:"user_id" binding:"required"`
	TenantID     string                 `json:"tenant_id" binding:"required"`
	ResourceType string                 `json:"resource_type" binding:"required"`
	ResourceID   string                 `json:"resource_id" binding:"required"`
	Action       string                 `json:"action" binding:"required"`
	Context      map[string]interface{} `json:"context"`
}

func (h *AuthzHandler) DryRun(c *gin.Context) {
	var req authzDryRunRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	result, err := h.authz.DryRun(c.Request.Context(), service.AuthzRequest{
		UserID:       req.UserID,
		TenantID:     req.TenantID,
		ResourceType: req.ResourceType,
		ResourceID:   req.ResourceID,
		Action:       req.Action,
		Context:      req.Context,
	})
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "dry-run check failed")
		return
	}

	c.JSON(http.StatusOK, authzCheckResponse{
		Allowed:   result.Allowed,
		Reason:    result.Reason,
		MatchedBy: result.MatchedBy,
	})
}

// ACL handlers
type aclGrantRequest struct {
	SubjectType   string `json:"subject_type" binding:"required,oneof=user team role"`
	SubjectID     string `json:"subject_id" binding:"required"`
	ResourceType  string `json:"resource_type" binding:"required"`
	ResourceID    string `json:"resource_id" binding:"required"`
	Permission    string `json:"permission" binding:"required"`
	Effect        string `json:"effect" binding:"oneof=allow deny"`
}

type aclResponse struct {
	ID           string `json:"id"`
	SubjectType  string `json:"subject_type"`
	SubjectID    string `json:"subject_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Permission   string `json:"permission"`
	Effect       string `json:"effect"`
}

func toACLResponse(acl *domain.ACLPermission) aclResponse {
	return aclResponse{
		ID:           acl.ID,
		SubjectType:  acl.SubjectType,
		SubjectID:    acl.SubjectID,
		ResourceType: acl.ResourceType,
		ResourceID:   acl.ResourceID,
		Permission:   acl.Permission,
		Effect:       acl.Effect,
	}
}

func (h *AuthzHandler) GrantACL(c *gin.Context) {
	tenantID := c.Param("tenantId")
	var req aclGrantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	acl, err := h.acl.Grant(c.Request.Context(), tenantID, service.ACLGrantRequest{
		SubjectType:   req.SubjectType,
		SubjectID:     req.SubjectID,
		ResourceType:  req.ResourceType,
		ResourceID:    req.ResourceID,
		Permission:    req.Permission,
		Effect:        req.Effect,
	})
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to grant ACL")
		return
	}
	c.JSON(http.StatusCreated, toACLResponse(acl))
}

func (h *AuthzHandler) RevokeACL(c *gin.Context) {
	tenantID := c.Param("tenantId")
	subjectType := c.Query("subject_type")
	subjectID := c.Query("subject_id")
	resourceType := c.Query("resource_type")
	resourceID := c.Query("resource_id")

	if err := h.acl.Revoke(c.Request.Context(), tenantID, subjectType, subjectID, resourceType, resourceID); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to revoke ACL")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AuthzHandler) ListACLBySubject(c *gin.Context) {
	tenantID := c.Param("tenantId")
	subjectType := c.Query("subject_type")
	subjectID := c.Query("subject_id")

	acls, err := h.acl.ListBySubject(c.Request.Context(), tenantID, subjectType, subjectID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list ACLs")
		return
	}
	resp := make([]aclResponse, 0, len(acls))
	for _, acl := range acls {
		resp = append(resp, toACLResponse(acl))
	}
	c.JSON(http.StatusOK, resp)
}

func (h *AuthzHandler) ListACLByResource(c *gin.Context) {
	tenantID := c.Param("tenantId")
	resourceType := c.Query("resource_type")
	resourceID := c.Query("resource_id")

	acls, err := h.acl.ListByResource(c.Request.Context(), tenantID, resourceType, resourceID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list ACLs")
		return
	}
	resp := make([]aclResponse, 0, len(acls))
	for _, acl := range acls {
		resp = append(resp, toACLResponse(acl))
	}
	c.JSON(http.StatusOK, resp)
}

// RolePermission handlers
type rolePermGrantRequest struct {
	RoleName   string `json:"role_name" binding:"required"`
	Permission string `json:"permission" binding:"required"`
}

type rolePermResponse struct {
	ID         string `json:"id"`
	RoleName   string `json:"role_name"`
	Permission string `json:"permission"`
}

func toRolePermResponse(rp *domain.RolePermission) rolePermResponse {
	return rolePermResponse{
		ID:         rp.ID,
		RoleName:   rp.RoleName,
		Permission: rp.Permission,
	}
}

func (h *AuthzHandler) GrantRolePermission(c *gin.Context) {
	tenantID := c.Param("tenantId")
	var req rolePermGrantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	rp, err := h.rolePerms.Grant(c.Request.Context(), tenantID, req.RoleName, req.Permission)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to grant role permission")
		return
	}
	c.JSON(http.StatusCreated, toRolePermResponse(rp))
}

func (h *AuthzHandler) RevokeRolePermission(c *gin.Context) {
	tenantID := c.Param("tenantId")
	roleName := c.Param("roleName")
	permission := c.Query("permission")

	if err := h.rolePerms.Revoke(c.Request.Context(), tenantID, roleName, permission); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to revoke role permission")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AuthzHandler) RevokeAllRolePermissions(c *gin.Context) {
	tenantID := c.Param("tenantId")
	roleName := c.Param("roleName")

	if err := h.rolePerms.RevokeAllForRole(c.Request.Context(), tenantID, roleName); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to revoke role permissions")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AuthzHandler) ListRolePermissions(c *gin.Context) {
	tenantID := c.Param("tenantId")
	roleName := c.Param("roleName")

	rps, err := h.rolePerms.ListByRole(c.Request.Context(), tenantID, roleName)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list role permissions")
		return
	}
	resp := make([]rolePermResponse, 0, len(rps))
	for _, rp := range rps {
		resp = append(resp, toRolePermResponse(rp))
	}
	c.JSON(http.StatusOK, resp)
}

// Permission handlers
type permissionCreateRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

type permissionResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func toPermissionResponse(p *domain.Permission) permissionResponse {
	return permissionResponse{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
	}
}

func (h *AuthzHandler) CreatePermission(c *gin.Context) {
	tenantID := c.Param("tenantId")
	var req permissionCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	perm, err := h.perms.Create(c.Request.Context(), tenantID, req.Name, req.Description)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to create permission")
		return
	}
	c.JSON(http.StatusCreated, toPermissionResponse(perm))
}

func (h *AuthzHandler) GetPermission(c *gin.Context) {
	id := c.Param("id")
	perm, err := h.perms.Get(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrACLNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "permission not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to get permission")
		return
	}
	c.JSON(http.StatusOK, toPermissionResponse(perm))
}

func (h *AuthzHandler) ListPermissions(c *gin.Context) {
	tenantID := c.Param("tenantId")
	perms, err := h.perms.List(c.Request.Context(), tenantID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list permissions")
		return
	}
	resp := make([]permissionResponse, 0, len(perms))
	for _, p := range perms {
		resp = append(resp, toPermissionResponse(p))
	}
	c.JSON(http.StatusOK, resp)
}

func (h *AuthzHandler) DeletePermission(c *gin.Context) {
	id := c.Param("id")
	if err := h.perms.Delete(c.Request.Context(), id); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to delete permission")
		return
	}
	c.Status(http.StatusNoContent)
}

// Policy handlers
type policyCreateRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	Rego        string `json:"rego" binding:"required"`
}

type policyResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Rego        string `json:"rego"`
	Version     int    `json:"version"`
	IsActive    bool   `json:"is_active"`
}

func toPolicyResponse(p *domain.Policy) policyResponse {
	return policyResponse{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Rego:        p.Rego,
		Version:     p.Version,
		IsActive:    p.IsActive,
	}
}

func (h *AuthzHandler) CreatePolicy(c *gin.Context) {
	tenantID := c.Param("tenantId")
	var req policyCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	policy, err := h.policy.Create(c.Request.Context(), tenantID, req.Name, req.Description, req.Rego)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to create policy")
		return
	}
	c.JSON(http.StatusCreated, toPolicyResponse(policy))
}

func (h *AuthzHandler) GetPolicy(c *gin.Context) {
	id := c.Param("id")
	policy, err := h.policy.Get(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrACLNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "policy not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to get policy")
		return
	}
	c.JSON(http.StatusOK, toPolicyResponse(policy))
}

func (h *AuthzHandler) ListPolicies(c *gin.Context) {
	tenantID := c.Param("tenantId")
	policies, err := h.policy.List(c.Request.Context(), tenantID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to list policies")
		return
	}
	resp := make([]policyResponse, 0, len(policies))
	for _, p := range policies {
		resp = append(resp, toPolicyResponse(p))
	}
	c.JSON(http.StatusOK, resp)
}

func (h *AuthzHandler) ActivatePolicy(c *gin.Context) {
	tenantID := c.Param("tenantId")
	id := c.Param("id")
	if err := h.policy.Activate(c.Request.Context(), tenantID, id); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to activate policy")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AuthzHandler) DeactivatePolicy(c *gin.Context) {
	id := c.Param("id")
	if err := h.policy.Deactivate(c.Request.Context(), id); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to deactivate policy")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AuthzHandler) DeletePolicy(c *gin.Context) {
	id := c.Param("id")
	if err := h.policy.Delete(c.Request.Context(), id); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to delete policy")
		return
	}
	c.Status(http.StatusNoContent)
}