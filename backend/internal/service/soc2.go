package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

type SOC2Service struct {
	users           domain.UserRepository
	memberships     domain.MembershipRepository
	teamMemberships domain.TeamMembershipRepository
	teams           domain.TeamRepository
	acl             *ACLService
	rolePerms       *RolePermissionService
	auditLogs       domain.AuditLogRepository
}

func NewSOC2Service(
	users domain.UserRepository,
	memberships domain.MembershipRepository,
	teamMemberships domain.TeamMembershipRepository,
	teams domain.TeamRepository,
	acl *ACLService,
	rolePerms *RolePermissionService,
	auditLogs domain.AuditLogRepository,
) *SOC2Service {
	return &SOC2Service{
		users:           users,
		memberships:     memberships,
		teamMemberships: teamMemberships,
		teams:           teams,
		acl:             acl,
		rolePerms:       rolePerms,
		auditLogs:       auditLogs,
	}
}

type AccessReviewReport struct {
	GeneratedAt   time.Time
	GeneratedBy   string
	TenantID      string
	Summary       ReviewSummary
	UserAccess    []UserAccessEntry
	StaleGrants   []StaleGrantEntry
	PolicyChanges []PolicyChangeEntry
}

type ReviewSummary struct {
	TotalUsers           int
	TotalRoles           int
	TotalPermissions     int
	StaleGrants          int
	UsersWithNoAccess    int
	AdminsCount          int
}

type UserAccessEntry struct {
	UserID       string
	UserEmail    string
	TenantID     string
	Roles        []string
	TeamRoles    map[string][]string
	DirectACLs   int
	EffectivePermissions []string
	LastLogin    *time.Time
	IsAdmin      bool
}

type StaleGrantEntry struct {
	UserID          string
	UserEmail       string
	GrantType       string // "role", "acl", "team_role"
	GrantDetails    string
	LastUsed        *time.Time
	DaysSinceUse    int
	Recommendation  string
}

type PolicyChangeEntry struct {
	PolicyID      string
	PolicyName    string
	ChangedBy     string
	ChangedAt     time.Time
	ChangeType    string // "created", "updated", "activated", "deactivated"
	BeforeState   map[string]any
	AfterState    map[string]any
}

type AccessReviewFilter struct {
	TenantID       string
	StartDate      time.Time
	EndDate        time.Time
	IncludeStale   bool
	StaleThreshold int // days
	UserIDs        []string
	RoleNames      []string
}

func (s *SOC2Service) GenerateAccessReview(ctx context.Context, filter AccessReviewFilter, generatedBy string) (*AccessReviewReport, error) {
	report := &AccessReviewReport{
		GeneratedAt: time.Now(),
		GeneratedBy: generatedBy,
		TenantID:    filter.TenantID,
	}

	// Get all users in tenant
	// This would require a user listing by tenant - simplified for now
	users, err := s.getUsersInTenant(ctx, filter.TenantID)
	if err != nil {
		return nil, err
	}

	report.Summary.TotalUsers = len(users)

	for _, user := range users {
		entry, err := s.buildUserAccessEntry(ctx, filter.TenantID, user)
		if err != nil {
			return nil, err
		}
		report.UserAccess = append(report.UserAccess, entry)

		// Check for stale grants
		staleGrants := s.checkStaleGrants(ctx, filter, user, entry)
		report.StaleGrants = append(report.StaleGrants, staleGrants...)
		report.Summary.StaleGrants += len(staleGrants)
	}

	// Get policy changes
	policyChanges, err := s.getPolicyChanges(ctx, filter)
	if err != nil {
		return nil, err
	}
	report.PolicyChanges = policyChanges

	return report, nil
}

func (s *SOC2Service) buildUserAccessEntry(ctx context.Context, tenantID string, user *domain.User) (UserAccessEntry, error) {
	entry := UserAccessEntry{
		UserID:    user.ID,
		UserEmail: user.Email,
		TenantID:  tenantID,
	}

	// Get tenant membership
	membership, err := s.memberships.FindByUserAndTenant(ctx, user.ID, tenantID)
	if err != nil {
		if !errors.Is(err, domain.ErrMembershipNotFound) {
			return entry, err
		}
	} else {
		entry.Roles = membership.Roles
	}

	// Get team memberships
	teamMemberships, err := s.teamMemberships.ListByUser(ctx, user.ID)
	if err != nil {
		return entry, err
	}

	entry.TeamRoles = make(map[string][]string)
	for _, tm := range teamMemberships {
		team, err := s.teams.FindByID(ctx, tm.TeamID)
		if err != nil {
			continue
		}
		if team.TenantID == tenantID {
			entry.TeamRoles[team.Name] = tm.Roles
		}
	}

	// Get direct ACLs
	acls, err := s.acl.ListBySubject(ctx, tenantID, "user", user.ID)
	if err != nil {
		return entry, err
	}
	entry.DirectACLs = len(acls)

	// Get effective permissions (would use authorization service in real impl)
	entry.EffectivePermissions = s.getEffectivePermissions(ctx, tenantID, user.ID)

	// Check if admin
	for _, role := range entry.Roles {
		if role == "admin" {
			entry.IsAdmin = true
			break
		}
	}

	return entry, nil
}

func (s *SOC2Service) checkStaleGrants(ctx context.Context, filter AccessReviewFilter, user *domain.User, entry UserAccessEntry) []StaleGrantEntry {
	var stale []StaleGrantEntry
	threshold := time.Now().AddDate(0, 0, -filter.StaleThreshold)

	// Check roles
	for _, role := range entry.Roles {
		if entry.IsAdmin && role == "admin" {
			continue // Don't flag admin role as stale
		}
		// In real impl, would check last usage from audit logs
		lastUsed := time.Now().AddDate(0, -2, 0) // Simulated
		if lastUsed.Before(threshold) {
			stale = append(stale, StaleGrantEntry{
				UserID:         entry.UserID,
				UserEmail:      entry.UserEmail,
				GrantType:      "role",
				GrantDetails:   role,
				LastUsed:       &lastUsed,
				DaysSinceUse:   int(time.Since(lastUsed).Hours() / 24),
				Recommendation: "Review if role still needed",
			})
		}
	}

	// Check team roles
	for teamName, roles := range entry.TeamRoles {
		for _, role := range roles {
			lastUsed := time.Now().AddDate(0, -1, 0) // Simulated
			if lastUsed.Before(threshold) {
				stale = append(stale, StaleGrantEntry{
					UserID:         entry.UserID,
					UserEmail:      entry.UserEmail,
					GrantType:      "team_role",
					GrantDetails:   fmt.Sprintf("%s:%s", teamName, role),
					LastUsed:       &lastUsed,
					DaysSinceUse:   int(time.Since(lastUsed).Hours() / 24),
					Recommendation: "Review team membership",
				})
			}
		}
	}

	// Check direct ACLs
	for i := 0; i < entry.DirectACLs; i++ {
		lastUsed := time.Now().AddDate(0, -3, 0) // Simulated
		if lastUsed.Before(threshold) {
			stale = append(stale, StaleGrantEntry{
				UserID:         entry.UserID,
				UserEmail:      entry.UserEmail,
				GrantType:      "acl",
				GrantDetails:   "Direct ACL grant",
				LastUsed:       &lastUsed,
				DaysSinceUse:   int(time.Since(lastUsed).Hours() / 24),
				Recommendation: "Review if ACL still needed",
			})
		}
	}

	return stale
}

func (s *SOC2Service) getEffectivePermissions(ctx context.Context, tenantID, userID string) []string {
	var permissions []string

	// Get from roles
	membership, err := s.memberships.FindByUserAndTenant(ctx, userID, tenantID)
	if err == nil {
		for _, role := range membership.Roles {
			rolePerms, _ := s.rolePerms.ListByRole(ctx, tenantID, role)
			for _, rp := range rolePerms {
				permissions = append(permissions, rp.Permission)
			}
		}
	}

	// Get from team roles
	teamMemberships, _ := s.teamMemberships.ListByUser(ctx, userID)
	for _, tm := range teamMemberships {
		team, _ := s.teams.FindByID(ctx, tm.TeamID)
		if team != nil && team.TenantID == tenantID {
			for _, role := range tm.Roles {
				rolePerms, _ := s.rolePerms.ListByRole(ctx, tenantID, role)
				for _, rp := range rolePerms {
					permissions = append(permissions, rp.Permission)
				}
			}
		}
	}

	// Get from direct ACLs
	acls, _ := s.acl.ListBySubject(ctx, tenantID, "user", userID)
	for _, acl := range acls {
		if acl.Effect == "allow" {
			permissions = append(permissions, acl.Permission)
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	unique := []string{}
	for _, p := range permissions {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	return unique
}

func (s *SOC2Service) getPolicyChanges(ctx context.Context, filter AccessReviewFilter) ([]PolicyChangeEntry, error) {
	// In real implementation, would query audit logs for policy-related events
	// For now, return empty
	return []PolicyChangeEntry{}, nil
}

func (s *SOC2Service) getUsersInTenant(ctx context.Context, tenantID string) ([]*domain.User, error) {
	// In real implementation, would list users by tenant membership
	// For now, return empty
	return []*domain.User{}, nil
}

