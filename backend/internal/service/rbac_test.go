package service_test

import (
	"testing"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
)

func TestRBACServiceAllow(t *testing.T) {
	rbac := service.NewRBACService()

	cases := []struct {
		name       string
		roles      []string
		permission string
		want       bool
	}{
		{"member self:read", []string{"member"}, "self:read", true},
		{"member users:write denied", []string{"member"}, "users:write", false},
		{"admin users:write", []string{"admin"}, "users:write", true},
		{"unknown role denied", []string{"guest"}, "self:read", false},
		{"no roles denied", nil, "self:read", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rbac.Allow(tc.roles, tc.permission); got != tc.want {
				t.Fatalf("Allow(%v, %q) = %v, want %v", tc.roles, tc.permission, got, tc.want)
			}
		})
	}
}
