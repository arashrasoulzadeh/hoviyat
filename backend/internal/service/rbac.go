package service

// Role-permission grants for the walking skeleton. A proper Role/Permission
// store (backed by Postgres) arrives with the ACL/ABAC build stage; for now
// this is a static, in-memory table matching the PRD's "coarse-grained
// RBAC" requirement (§3).
var rolePermissions = map[string][]string{
	"member": {"self:read", "self:write"},
	"admin":  {"self:read", "self:write", "users:read", "users:write"},
}

// RBACService answers coarse-grained role-based authorization checks.
type RBACService struct{}

func NewRBACService() *RBACService {
	return &RBACService{}
}

// Allow reports whether any of the given roles grants the permission.
func (s *RBACService) Allow(roles []string, permission string) bool {
	for _, role := range roles {
		for _, p := range rolePermissions[role] {
			if p == permission {
				return true
			}
		}
	}
	return false
}
