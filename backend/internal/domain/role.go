package domain

// Role is a coarse-grained RBAC grant. ACL/ABAC (resource-instance
// overrides, OPA-evaluated policies) arrive in a later build stage; the
// walking skeleton only needs role membership checks.
type Role struct {
	Name        string
	Permissions []string
}

// HasPermission reports whether the role grants the given permission.
func (r Role) HasPermission(permission string) bool {
	for _, p := range r.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}
