package db

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
)

var (
	ErrNotFound      = errors.New("record not found")
	ErrAlreadyExists = errors.New("record already exists")
	ErrUnauthorized  = errors.New("unauthorized or forbidden")
)

// Store defines the persistence contract for the Utah Common AuthN/AuthZ system.
type Store interface {
	// Identity Providers (UtahID & External OIDC)
	CreateIdentityProvider(ctx context.Context, idp domain.IdentityProvider) (*domain.IdentityProvider, error)
	GetIdentityProviderByIssuer(ctx context.Context, issuerURL string) (*domain.IdentityProvider, error)
	GetIdentityProviderBySlug(ctx context.Context, slug string) (*domain.IdentityProvider, error)
	ListIdentityProviders(ctx context.Context) ([]domain.IdentityProvider, error)

	// Users & Federated Identity Resolution
	ResolveOrProvisionUser(
		ctx context.Context,
		idp *domain.IdentityProvider,
		subject, email, displayName string,
		emailVerified bool,
		rawClaims map[string]any,
		externalGroups []string,
	) (*domain.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	ListUsers(ctx context.Context, limit, offset int) ([]domain.User, error)

	// Organizations & Groups
	CreateOrganization(ctx context.Context, org domain.Organization) (*domain.Organization, error)
	ListOrganizations(ctx context.Context) ([]domain.Organization, error)
	CreateGroup(ctx context.Context, grp domain.Group) (*domain.Group, error)
	AddUserToGroup(ctx context.Context, groupID, userID uuid.UUID, expiresAt *time.Time) error

	// Applications & IdP Bindings
	CreateApplication(ctx context.Context, app domain.Application) (*domain.Application, error)
	GetApplicationBySlug(ctx context.Context, slug string) (*domain.Application, error)
	ListApplications(ctx context.Context) ([]domain.Application, error)
	BindAppIdentityProvider(ctx context.Context, binding domain.AppIdentityProvider) error
	GetAppIdentityProvider(ctx context.Context, appID, idpID uuid.UUID) (*domain.AppIdentityProvider, error)

	// Permissions & Roles
	CreatePermission(ctx context.Context, perm domain.Permission) (*domain.Permission, error)
	ListPermissionsByApp(ctx context.Context, appID uuid.UUID) ([]domain.Permission, error)
	CreateRole(ctx context.Context, role domain.Role) (*domain.Role, error)
	GetRoleBySlug(ctx context.Context, appID uuid.UUID, slug string) (*domain.Role, error)
	ListRolesByApp(ctx context.Context, appID uuid.UUID) ([]domain.Role, error)
	AttachPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID, conditions domain.ABACConditions) error

	// Scoped Role Assignments & Zero Trust Querying
	CreateRoleAssignment(ctx context.Context, ra domain.RoleAssignment) (*domain.RoleAssignment, error)
	DeleteRoleAssignment(ctx context.Context, appID, assignmentID uuid.UUID) error
	ListRoleAssignmentsByApp(ctx context.Context, appID uuid.UUID) ([]domain.RoleAssignment, error)
	ListUserActiveRolesForApp(ctx context.Context, userID, appID uuid.UUID, orgID *uuid.UUID) ([]string, error)
	FindMatchingGrants(ctx context.Context, req domain.AuthorizeRequest) ([]domain.MatchedGrant, error)

	// Audit Logs
	InsertAuditLog(ctx context.Context, entry domain.AuditLog) error
}
