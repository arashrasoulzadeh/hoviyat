package service

import (
	"context"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

type AuthorizationService struct {
	rbac       *RBACService
	acl        *ACLService
	abac       *ABACService
	rolePerms  *RolePermissionService
	policies   *PolicyService
	cache      *AuthzCache
	membership domain.MembershipRepository
	teamMemberships domain.TeamMembershipRepository
	teams      domain.TeamRepository
}

func NewAuthorizationService(
	rbac *RBACService,
	acl *ACLService,
	abac *ABACService,
	rolePerms *RolePermissionService,
	policies *PolicyService,
	cache *AuthzCache,
	membership domain.MembershipRepository,
	teamMemberships domain.TeamMembershipRepository,
	teams domain.TeamRepository,
) *AuthorizationService {
	return &AuthorizationService{
		rbac:       rbac,
		acl:        acl,
		abac:       abac,
		rolePerms:  rolePerms,
		policies:   policies,
		cache:      cache,
		membership: membership,
		teamMemberships: teamMemberships,
		teams:      teams,
	}
}

type AuthzRequest struct {
	UserID     string
	TenantID   string
	ResourceType string
	ResourceID   string
	Action       string
	Context    map[string]interface{} // Additional context for ABAC
}

type AuthzResult struct {
	Allowed bool
	Reason  string
	MatchedBy string // "rbac", "acl", "abac"
}

func (s *AuthorizationService) Check(ctx context.Context, req AuthzRequest) (*AuthzResult, error) {
	// Try cache first
	if s.cache != nil {
		if cached, ok := s.cache.Get(ctx, req.TenantID, req.UserID, req.ResourceType, req.ResourceID, req.Action); ok {
			return cached, nil
		}
	}

	// Step 1: Get user's effective roles for the tenant (tenant + team roles)
	roles, err := s.getEffectiveRoles(ctx, req.UserID, req.TenantID)
	if err != nil {
		return nil, err
	}

	// Step 2: Check RBAC (role-based permissions)
	permission := s.actionToPermission(req.ResourceType, req.Action)
	if s.rbac.Allow(roles, permission) {
		result := &AuthzResult{Allowed: true, Reason: "granted by role", MatchedBy: "rbac"}
		if s.cache != nil {
			s.cache.Set(ctx, req.TenantID, req.UserID, req.ResourceType, req.ResourceID, req.Action, result)
		}
		return result, nil
	}

	// Step 3: Check ACL (resource-instance level)
	// Check user-level ACL
	if acl, err := s.acl.Check(ctx, req.TenantID, "user", req.UserID, req.ResourceType, req.ResourceID, permission); err == nil {
		var result *AuthzResult
		if acl.Effect == "allow" {
			result = &AuthzResult{Allowed: true, Reason: "granted by user ACL", MatchedBy: "acl"}
		} else {
			result = &AuthzResult{Allowed: false, Reason: "denied by user ACL", MatchedBy: "acl"}
		}
		if s.cache != nil {
			s.cache.Set(ctx, req.TenantID, req.UserID, req.ResourceType, req.ResourceID, req.Action, result)
		}
		return result, nil
	}

	// Check team-level ACLs
	teamMemberships, err := s.teamMemberships.ListByUser(ctx, req.UserID)
	if err == nil {
		for _, tm := range teamMemberships {
			team, err := s.teams.FindByID(ctx, tm.TeamID)
			if err != nil || team.TenantID != req.TenantID {
				continue
			}
			if acl, err := s.acl.Check(ctx, req.TenantID, "team", tm.TeamID, req.ResourceType, req.ResourceID, permission); err == nil {
				var result *AuthzResult
				if acl.Effect == "allow" {
					result = &AuthzResult{Allowed: true, Reason: "granted by team ACL", MatchedBy: "acl"}
				} else {
					result = &AuthzResult{Allowed: false, Reason: "denied by team ACL", MatchedBy: "acl"}
				}
				if s.cache != nil {
					s.cache.Set(ctx, req.TenantID, req.UserID, req.ResourceType, req.ResourceID, req.Action, result)
				}
				return result, nil
			}
		}
	}

	// Check role-level ACLs
	for _, role := range roles {
		if acl, err := s.acl.Check(ctx, req.TenantID, "role", role, req.ResourceType, req.ResourceID, permission); err == nil {
			var result *AuthzResult
			if acl.Effect == "allow" {
				result = &AuthzResult{Allowed: true, Reason: "granted by role ACL", MatchedBy: "acl"}
			} else {
				result = &AuthzResult{Allowed: false, Reason: "denied by role ACL", MatchedBy: "acl"}
			}
			if s.cache != nil {
				s.cache.Set(ctx, req.TenantID, req.UserID, req.ResourceType, req.ResourceID, req.Action, result)
			}
			return result, nil
		}
	}

	// Step 4: Check ABAC (OPA policies)
	activePolicies, err := s.policies.ListActive(ctx, req.TenantID)
	if err == nil && len(activePolicies) > 0 {
		// Prepare user attributes
		userAttrs := map[string]interface{}{
			"id":    req.UserID,
			"roles": roles,
		}

		resourceAttrs := map[string]interface{}{
			"type": req.ResourceType,
			"id":   req.ResourceID,
		}

		input := PolicyEvaluationInput{
			User:     userAttrs,
			Resource: resourceAttrs,
			Action:   req.Action,
			Context:  req.Context,
		}

		policyIDs := make([]string, 0, len(activePolicies))
		for _, p := range activePolicies {
			policyIDs = append(policyIDs, p.ID)
			// Prepare query if not already prepared
			if _, ok := s.abac.preparedQueries[p.ID]; !ok {
				s.abac.PrepareQuery(ctx, p.ID, p.Rego)
			}
		}

		abacResults, err := s.abac.EvaluateAll(ctx, policyIDs, input)
		if err == nil {
			for policyID, allowed := range abacResults {
				var result *AuthzResult
				if allowed {
					result = &AuthzResult{Allowed: true, Reason: "granted by policy " + policyID, MatchedBy: "abac"}
				} else {
					result = &AuthzResult{Allowed: false, Reason: "denied by policy", MatchedBy: "abac"}
				}
				if s.cache != nil {
					s.cache.Set(ctx, req.TenantID, req.UserID, req.ResourceType, req.ResourceID, req.Action, result)
				}
				return result, nil
			}
		}
	}

	// Default deny
	result := &AuthzResult{Allowed: false, Reason: "no matching rule", MatchedBy: "none"}
	if s.cache != nil {
		s.cache.Set(ctx, req.TenantID, req.UserID, req.ResourceType, req.ResourceID, req.Action, result)
	}
	return result, nil
}

func (s *AuthorizationService) getEffectiveRoles(ctx context.Context, userID, tenantID string) ([]string, error) {
	membership, err := s.membership.FindByUserAndTenant(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}

	roles := membership.Roles

	teamMemberships, err := s.teamMemberships.ListByUser(ctx, userID)
	if err != nil {
		return roles, nil
	}
	for _, tm := range teamMemberships {
		team, err := s.teams.FindByID(ctx, tm.TeamID)
		if err != nil {
			continue
		}
		if team.TenantID == tenantID {
			roles = append(roles, tm.Roles...)
		}
	}

	return roles, nil
}

func (s *AuthorizationService) actionToPermission(resourceType, action string) string {
	// Convert action to permission format: resource:action
	// e.g., "read" -> "document:read"
	return resourceType + ":" + action
}

// DryRun simulates an authorization check without side effects
func (s *AuthorizationService) DryRun(ctx context.Context, req AuthzRequest) (*AuthzResult, error) {
	return s.Check(ctx, req)
}