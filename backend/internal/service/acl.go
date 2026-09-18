package service

import (
	"context"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

type ACLService struct {
	acl domain.ACLRepository
}

func NewACLService(acl domain.ACLRepository) *ACLService {
	return &ACLService{acl: acl}
}

type ACLGrantRequest struct {
	SubjectType   string
	SubjectID     string
	ResourceType  string
	ResourceID    string
	Permission    string
	Effect        string // "allow" or "deny"
}

func (s *ACLService) Grant(ctx context.Context, tenantID string, req ACLGrantRequest) (*domain.ACLPermission, error) {
	if req.Effect == "" {
		req.Effect = "allow"
	}
	acl := &domain.ACLPermission{
		TenantID:      tenantID,
		SubjectType:   req.SubjectType,
		SubjectID:     req.SubjectID,
		ResourceType:  req.ResourceType,
		ResourceID:    req.ResourceID,
		Permission:    req.Permission,
		Effect:        req.Effect,
	}
	if err := s.acl.Create(ctx, acl); err != nil {
		return nil, err
	}
	return acl, nil
}

func (s *ACLService) Revoke(ctx context.Context, tenantID, subjectType, subjectID, resourceType, resourceID string) error {
	return s.acl.DeleteBySubjectAndResource(ctx, tenantID, subjectType, subjectID, resourceType, resourceID)
}

func (s *ACLService) RevokeByID(ctx context.Context, id string) error {
	return s.acl.Delete(ctx, id)
}

func (s *ACLService) ListBySubject(ctx context.Context, tenantID, subjectType, subjectID string) ([]*domain.ACLPermission, error) {
	return s.acl.FindBySubject(ctx, tenantID, subjectType, subjectID)
}

func (s *ACLService) ListByResource(ctx context.Context, tenantID, resourceType, resourceID string) ([]*domain.ACLPermission, error) {
	return s.acl.FindByResource(ctx, tenantID, resourceType, resourceID)
}

func (s *ACLService) Check(ctx context.Context, tenantID, subjectType, subjectID, resourceType, resourceID, permission string) (*domain.ACLPermission, error) {
	return s.acl.CheckPermission(ctx, tenantID, subjectType, subjectID, resourceType, resourceID, permission)
}

type RolePermissionService struct {
	rolePerms domain.RolePermissionRepository
}

func NewRolePermissionService(rolePerms domain.RolePermissionRepository) *RolePermissionService {
	return &RolePermissionService{rolePerms: rolePerms}
}

func (s *RolePermissionService) Grant(ctx context.Context, tenantID, roleName, permission string) (*domain.RolePermission, error) {
	rp := &domain.RolePermission{
		TenantID:   tenantID,
		RoleName:   roleName,
		Permission: permission,
	}
	if err := s.rolePerms.Create(ctx, rp); err != nil {
		return nil, err
	}
	return rp, nil
}

func (s *RolePermissionService) Revoke(ctx context.Context, tenantID, roleName, permission string) error {
	rps, err := s.rolePerms.FindByRole(ctx, tenantID, roleName)
	if err != nil {
		return err
	}
	for _, rp := range rps {
		if rp.Permission == permission {
			return s.rolePerms.Delete(ctx, rp.ID)
		}
	}
	return domain.ErrACLNotFound
}

func (s *RolePermissionService) RevokeAllForRole(ctx context.Context, tenantID, roleName string) error {
	return s.rolePerms.DeleteByRole(ctx, tenantID, roleName)
}

func (s *RolePermissionService) ListByRole(ctx context.Context, tenantID, roleName string) ([]*domain.RolePermission, error) {
	return s.rolePerms.FindByRole(ctx, tenantID, roleName)
}

func (s *RolePermissionService) ListByTenant(ctx context.Context, tenantID string) ([]*domain.RolePermission, error) {
	return s.rolePerms.FindByTenant(ctx, tenantID)
}

type PermissionService struct {
	perms domain.PermissionRepository
}

func NewPermissionService(perms domain.PermissionRepository) *PermissionService {
	return &PermissionService{perms: perms}
}

func (s *PermissionService) Create(ctx context.Context, tenantID, name, description string) (*domain.Permission, error) {
	perm := &domain.Permission{
		TenantID:    tenantID,
		Name:        name,
		Description: description,
	}
	if err := s.perms.Create(ctx, perm); err != nil {
		return nil, err
	}
	return perm, nil
}

func (s *PermissionService) Get(ctx context.Context, id string) (*domain.Permission, error) {
	return s.perms.FindByID(ctx, id)
}

func (s *PermissionService) List(ctx context.Context, tenantID string) ([]*domain.Permission, error) {
	return s.perms.FindByTenant(ctx, tenantID)
}

func (s *PermissionService) Delete(ctx context.Context, id string) error {
	return s.perms.Delete(ctx, id)
}