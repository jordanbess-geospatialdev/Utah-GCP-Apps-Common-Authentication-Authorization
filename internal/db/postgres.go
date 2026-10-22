package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
)

// PostgresStore implements Store backed by GCP Cloud SQL for PostgreSQL via pgxpool.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a new connection pool to Cloud SQL PostgreSQL.
func NewPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = 25
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pgx pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

// Close closes the underlying connection pool.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// ============================================================================
// 1. Identity Providers
// ============================================================================

func (s *PostgresStore) CreateIdentityProvider(ctx context.Context, idp domain.IdentityProvider) (*domain.IdentityProvider, error) {
	mappingsJSON, err := json.Marshal(idp.ClaimMappings)
	if err != nil {
		return nil, fmt.Errorf("marshal claim_mappings: %w", err)
	}

	const q = `
		INSERT INTO identity_providers (
			slug, name, provider_type, issuer_url, client_id, jwks_uri,
			claim_mappings, is_internal_state, auto_provision, is_active
		) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, $8, $9, $10)
		RETURNING id, created_at, updated_at
	`
	err = s.pool.QueryRow(ctx, q,
		idp.Slug, idp.Name, idp.ProviderType, idp.IssuerURL, idp.ClientID, idp.JWKSURI,
		mappingsJSON, idp.IsInternalState, idp.AutoProvision, idp.IsActive,
	).Scan(&idp.ID, &idp.CreatedAt, &idp.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert identity_provider: %w", err)
	}
	return &idp, nil
}

func (s *PostgresStore) GetIdentityProviderByIssuer(ctx context.Context, issuerURL string) (*domain.IdentityProvider, error) {
	const q = `
		SELECT id, slug, name, provider_type, issuer_url, client_id, COALESCE(jwks_uri, ''),
		       claim_mappings, is_internal_state, auto_provision, is_active, created_at, updated_at
		FROM identity_providers
		WHERE issuer_url = $1 AND is_active = TRUE
	`
	return s.scanIdP(s.pool.QueryRow(ctx, q, issuerURL))
}

func (s *PostgresStore) GetIdentityProviderBySlug(ctx context.Context, slug string) (*domain.IdentityProvider, error) {
	const q = `
		SELECT id, slug, name, provider_type, issuer_url, client_id, COALESCE(jwks_uri, ''),
		       claim_mappings, is_internal_state, auto_provision, is_active, created_at, updated_at
		FROM identity_providers
		WHERE slug = $1
	`
	return s.scanIdP(s.pool.QueryRow(ctx, q, slug))
}

func (s *PostgresStore) ListIdentityProviders(ctx context.Context) ([]domain.IdentityProvider, error) {
	const q = `
		SELECT id, slug, name, provider_type, issuer_url, client_id, COALESCE(jwks_uri, ''),
		       claim_mappings, is_internal_state, auto_provision, is_active, created_at, updated_at
		FROM identity_providers
		ORDER BY is_internal_state DESC, slug ASC
	`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []domain.IdentityProvider
	for rows.Next() {
		var idp domain.IdentityProvider
		var mappingsRaw []byte
		if err := rows.Scan(
			&idp.ID, &idp.Slug, &idp.Name, &idp.ProviderType, &idp.IssuerURL, &idp.ClientID, &idp.JWKSURI,
			&mappingsRaw, &idp.IsInternalState, &idp.AutoProvision, &idp.IsActive, &idp.CreatedAt, &idp.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(mappingsRaw, &idp.ClaimMappings)
		result = append(result, idp)
	}
	return result, rows.Err()
}

func (s *PostgresStore) scanIdP(row pgx.Row) (*domain.IdentityProvider, error) {
	var idp domain.IdentityProvider
	var mappingsRaw []byte
	err := row.Scan(
		&idp.ID, &idp.Slug, &idp.Name, &idp.ProviderType, &idp.IssuerURL, &idp.ClientID, &idp.JWKSURI,
		&mappingsRaw, &idp.IsInternalState, &idp.AutoProvision, &idp.IsActive, &idp.CreatedAt, &idp.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(mappingsRaw, &idp.ClaimMappings)
	return &idp, nil
}

// ============================================================================
// 2. Users & Federated Identities
// ============================================================================

func (s *PostgresStore) ResolveOrProvisionUser(
	ctx context.Context,
	idp *domain.IdentityProvider,
	subject, email, displayName string,
	emailVerified bool,
	rawClaims map[string]any,
	externalGroups []string,
) (*domain.User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	claimsBytes, _ := json.Marshal(rawClaims)

	// 1. Check if this (idp_id, idp_subject) is already linked
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT user_id FROM user_identities WHERE idp_id = $1 AND idp_subject = $2
	`, idp.ID, subject).Scan(&userID)

	if errors.Is(err, pgx.ErrNoRows) {
		// 2. If email is verified and matches an existing canonical user, link identity
		if emailVerified && normalizedEmail != "" {
			err = tx.QueryRow(ctx, `
				SELECT id FROM users WHERE LOWER(email) = $1
			`, normalizedEmail).Scan(&userID)
		}

		if errors.Is(err, pgx.ErrNoRows) {
			if !idp.AutoProvision {
				return nil, fmt.Errorf("%w: user not provisioned and JIT auto_provision is disabled for IdP %s", ErrUnauthorized, idp.Slug)
			}
			userType := "external_partner"
			if idp.IsInternalState {
				userType = "state_employee"
			}
			if displayName == "" {
				displayName = normalizedEmail
			}
			err = tx.QueryRow(ctx, `
				INSERT INTO users (email, email_verified, display_name, user_type, status, last_login_at)
				VALUES (NULLIF($1, ''), $2, $3, $4, 'active', NOW())
				RETURNING id
			`, normalizedEmail, emailVerified, displayName, userType).Scan(&userID)
			if err != nil {
				return nil, fmt.Errorf("provision JIT user: %w", err)
			}
		} else if err != nil {
			return nil, fmt.Errorf("lookup user by email: %w", err)
		}

		// Link the federated identity
		_, err = tx.Exec(ctx, `
			INSERT INTO user_identities (user_id, idp_id, idp_subject, idp_email, raw_claims, last_authenticated)
			VALUES ($1, $2, $3, NULLIF($4, ''), $5, NOW())
		`, userID, idp.ID, subject, normalizedEmail, claimsBytes)
		if err != nil {
			return nil, fmt.Errorf("insert user_identity: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("query user_identity: %w", err)
	} else {
		// Update existing identity timestamp and claims snapshot
		_, _ = tx.Exec(ctx, `
			UPDATE user_identities
			SET last_authenticated = NOW(), raw_claims = $3, idp_email = COALESCE(NULLIF($4, ''), idp_email)
			WHERE idp_id = $1 AND idp_subject = $2
		`, idp.ID, subject, claimsBytes, normalizedEmail)
		_, _ = tx.Exec(ctx, `UPDATE users SET last_login_at = NOW() WHERE id = $1`, userID)
	}

	// 3. Synchronize any mapped external IdP groups from OIDC claims
	if len(externalGroups) > 0 {
		_, err = tx.Exec(ctx, `
			INSERT INTO group_memberships (group_id, user_id)
			SELECT id, $1
			FROM groups
			WHERE external_idp_id = $2 AND external_group_id = ANY($3)
			ON CONFLICT DO NOTHING
		`, userID, idp.ID, externalGroups)
		if err != nil {
			return nil, fmt.Errorf("sync external group memberships: %w", err)
		}
	}

	var u domain.User
	var attrRaw []byte
	var emailNull *string
	err = tx.QueryRow(ctx, `
		SELECT id, email, email_verified, display_name, user_type, status, attributes, last_login_at, created_at, updated_at
		FROM users WHERE id = $1
	`, userID).Scan(
		&u.ID, &emailNull, &u.EmailVerified, &u.DisplayName, &u.UserType, &u.Status,
		&attrRaw, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if emailNull != nil {
		u.Email = *emailNull
	}
	_ = json.Unmarshal(attrRaw, &u.Attributes)

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *PostgresStore) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	var u domain.User
	var attrRaw []byte
	var emailNull *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, email_verified, display_name, user_type, status, attributes, last_login_at, created_at, updated_at
		FROM users WHERE id = $1
	`, id).Scan(
		&u.ID, &emailNull, &u.EmailVerified, &u.DisplayName, &u.UserType, &u.Status,
		&attrRaw, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if emailNull != nil {
		u.Email = *emailNull
	}
	_ = json.Unmarshal(attrRaw, &u.Attributes)
	return &u, nil
}

func (s *PostgresStore) ListUsers(ctx context.Context, limit, offset int) ([]domain.User, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, email_verified, display_name, user_type, status, attributes, last_login_at, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var u domain.User
		var attrRaw []byte
		var emailNull *string
		if err := rows.Scan(
			&u.ID, &emailNull, &u.EmailVerified, &u.DisplayName, &u.UserType, &u.Status,
			&attrRaw, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if emailNull != nil {
			u.Email = *emailNull
		}
		_ = json.Unmarshal(attrRaw, &u.Attributes)
		users = append(users, u)
	}
	return users, rows.Err()
}

// ============================================================================
// 3. Organizations & Groups
// ============================================================================

func (s *PostgresStore) CreateOrganization(ctx context.Context, org domain.Organization) (*domain.Organization, error) {
	metaBytes, _ := json.Marshal(org.Metadata)
	if len(metaBytes) == 0 {
		metaBytes = []byte("{}")
	}
	const q = `
		INSERT INTO organizations (slug, name, org_type, parent_id, hierarchy_path, is_active, metadata)
		VALUES ($1, $2, $3, $4, $5::ltree, $6, $7)
		RETURNING id, created_at, updated_at
	`
	err := s.pool.QueryRow(ctx, q,
		org.Slug, org.Name, org.OrgType, org.ParentID, org.HierarchyPath, org.IsActive, metaBytes,
	).Scan(&org.ID, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create organization: %w", err)
	}
	return &org, nil
}

func (s *PostgresStore) ListOrganizations(ctx context.Context) ([]domain.Organization, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, slug, name, org_type, parent_id, hierarchy_path::text, is_active, metadata, created_at, updated_at
		FROM organizations
		ORDER BY hierarchy_path ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orgs []domain.Organization
	for rows.Next() {
		var o domain.Organization
		var metaRaw []byte
		if err := rows.Scan(
			&o.ID, &o.Slug, &o.Name, &o.OrgType, &o.ParentID, &o.HierarchyPath,
			&o.IsActive, &metaRaw, &o.CreatedAt, &o.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(metaRaw, &o.Metadata)
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}

func (s *PostgresStore) CreateGroup(ctx context.Context, grp domain.Group) (*domain.Group, error) {
	const q = `
		INSERT INTO groups (organization_id, slug, name, description, external_idp_id, external_group_id)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''))
		RETURNING id, created_at
	`
	err := s.pool.QueryRow(ctx, q,
		grp.OrganizationID, grp.Slug, grp.Name, grp.Description, grp.ExternalIdPID, grp.ExternalGroupID,
	).Scan(&grp.ID, &grp.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}
	return &grp, nil
}

func (s *PostgresStore) AddUserToGroup(ctx context.Context, groupID, userID uuid.UUID, expiresAt *time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO group_memberships (group_id, user_id, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (group_id, user_id) DO UPDATE SET expires_at = EXCLUDED.expires_at
	`, groupID, userID, expiresAt)
	return err
}

// ============================================================================
// 4. Applications, Permissions & Roles (Dynamic Registration)
// ============================================================================

func (s *PostgresStore) CreateApplication(ctx context.Context, app domain.Application) (*domain.Application, error) {
	if app.TokenTTLSeconds <= 0 {
		app.TokenTTLSeconds = 900
	}
	if app.AllowedOrigins == nil {
		app.AllowedOrigins = []string{}
	}
	metaBytes, _ := json.Marshal(app.Metadata)
	if len(metaBytes) == 0 {
		metaBytes = []byte("{}")
	}
	const q = `
		INSERT INTO applications (
			slug, name, description, owner_org_id, allowed_origins,
			token_ttl_seconds, require_mfa, is_active, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at
	`
	err := s.pool.QueryRow(ctx, q,
		app.Slug, app.Name, app.Description, app.OwnerOrgID, app.AllowedOrigins,
		app.TokenTTLSeconds, app.RequireMFA, app.IsActive, metaBytes,
	).Scan(&app.ID, &app.CreatedAt, &app.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create application: %w", err)
	}
	return &app, nil
}

func (s *PostgresStore) GetApplicationBySlug(ctx context.Context, slug string) (*domain.Application, error) {
	var app domain.Application
	var metaRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, slug, name, COALESCE(description, ''), owner_org_id, allowed_origins,
		       token_ttl_seconds, require_mfa, is_active, metadata, created_at, updated_at
		FROM applications
		WHERE slug = $1
	`, slug).Scan(
		&app.ID, &app.Slug, &app.Name, &app.Description, &app.OwnerOrgID, &app.AllowedOrigins,
		&app.TokenTTLSeconds, &app.RequireMFA, &app.IsActive, &metaRaw, &app.CreatedAt, &app.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metaRaw, &app.Metadata)
	return &app, nil
}

func (s *PostgresStore) ListApplications(ctx context.Context) ([]domain.Application, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, slug, name, COALESCE(description, ''), owner_org_id, allowed_origins,
		       token_ttl_seconds, require_mfa, is_active, metadata, created_at, updated_at
		FROM applications
		ORDER BY slug ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []domain.Application
	for rows.Next() {
		var app domain.Application
		var metaRaw []byte
		if err := rows.Scan(
			&app.ID, &app.Slug, &app.Name, &app.Description, &app.OwnerOrgID, &app.AllowedOrigins,
			&app.TokenTTLSeconds, &app.RequireMFA, &app.IsActive, &metaRaw, &app.CreatedAt, &app.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(metaRaw, &app.Metadata)
		apps = append(apps, app)
	}
	return apps, rows.Err()
}

func (s *PostgresStore) BindAppIdentityProvider(ctx context.Context, binding domain.AppIdentityProvider) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO app_identity_providers (application_id, idp_id, allow_jit_signup, default_role_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (application_id, idp_id) DO UPDATE
		SET allow_jit_signup = EXCLUDED.allow_jit_signup,
		    default_role_id = EXCLUDED.default_role_id
	`, binding.ApplicationID, binding.IdPID, binding.AllowJITSignup, binding.DefaultRoleID)
	return err
}

func (s *PostgresStore) GetAppIdentityProvider(ctx context.Context, appID, idpID uuid.UUID) (*domain.AppIdentityProvider, error) {
	var b domain.AppIdentityProvider
	err := s.pool.QueryRow(ctx, `
		SELECT application_id, idp_id, allow_jit_signup, default_role_id
		FROM app_identity_providers
		WHERE application_id = $1 AND idp_id = $2
	`, appID, idpID).Scan(&b.ApplicationID, &b.IdPID, &b.AllowJITSignup, &b.DefaultRoleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func (s *PostgresStore) CreatePermission(ctx context.Context, perm domain.Permission) (*domain.Permission, error) {
	const q = `
		INSERT INTO permissions (application_id, resource_type, action, description)
		VALUES ($1, $2, $3, $4)
		RETURNING id, slug, created_at
	`
	err := s.pool.QueryRow(ctx, q,
		perm.ApplicationID, perm.ResourceType, perm.Action, perm.Description,
	).Scan(&perm.ID, &perm.Slug, &perm.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create permission: %w", err)
	}
	return &perm, nil
}

func (s *PostgresStore) ListPermissionsByApp(ctx context.Context, appID uuid.UUID) ([]domain.Permission, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, application_id, resource_type, action, slug, COALESCE(description, ''), created_at
		FROM permissions
		WHERE application_id = $1
		ORDER BY resource_type ASC, action ASC
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []domain.Permission
	for rows.Next() {
		var p domain.Permission
		if err := rows.Scan(&p.ID, &p.ApplicationID, &p.ResourceType, &p.Action, &p.Slug, &p.Description, &p.CreatedAt); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

func (s *PostgresStore) CreateRole(ctx context.Context, role domain.Role) (*domain.Role, error) {
	const q = `
		INSERT INTO roles (application_id, slug, name, description, is_system_role, inherits_from)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at
	`
	err := s.pool.QueryRow(ctx, q,
		role.ApplicationID, role.Slug, role.Name, role.Description, role.IsSystemRole, role.InheritsFrom,
	).Scan(&role.ID, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}
	return &role, nil
}

func (s *PostgresStore) GetRoleBySlug(ctx context.Context, appID uuid.UUID, slug string) (*domain.Role, error) {
	var r domain.Role
	err := s.pool.QueryRow(ctx, `
		SELECT id, application_id, slug, name, COALESCE(description, ''), is_system_role, inherits_from, created_at, updated_at
		FROM roles
		WHERE application_id = $1 AND slug = $2
	`, appID, slug).Scan(
		&r.ID, &r.ApplicationID, &r.Slug, &r.Name, &r.Description, &r.IsSystemRole, &r.InheritsFrom, &r.CreatedAt, &r.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *PostgresStore) ListRolesByApp(ctx context.Context, appID uuid.UUID) ([]domain.Role, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, application_id, slug, name, COALESCE(description, ''), is_system_role, inherits_from, created_at, updated_at
		FROM roles
		WHERE application_id = $1
		ORDER BY slug ASC
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []domain.Role
	for rows.Next() {
		var r domain.Role
		if err := rows.Scan(
			&r.ID, &r.ApplicationID, &r.Slug, &r.Name, &r.Description, &r.IsSystemRole, &r.InheritsFrom, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

func (s *PostgresStore) AttachPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID, conditions domain.ABACConditions) error {
	condBytes, err := json.Marshal(conditions)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, conditions)
		VALUES ($1, $2, $3)
		ON CONFLICT (role_id, permission_id) DO UPDATE SET conditions = EXCLUDED.conditions
	`, roleID, permissionID, condBytes)
	return err
}

// ============================================================================
// 5. Scoped Role Assignments & Single-Pass Zero Trust Evaluation Query
// ============================================================================

func (s *PostgresStore) CreateRoleAssignment(ctx context.Context, ra domain.RoleAssignment) (*domain.RoleAssignment, error) {
	if ra.Effect == "" {
		ra.Effect = domain.EffectAllow
	}
	if ra.StartsAt.IsZero() {
		ra.StartsAt = time.Now().UTC()
	}
	condBytes, err := json.Marshal(ra.Conditions)
	if err != nil {
		return nil, err
	}

	const q = `
		INSERT INTO role_assignments (
			application_id, role_id, principal_type, user_id, group_id,
			effect, organization_id, include_child_orgs, resource_type, resource_id,
			conditions, granted_by, justification, starts_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING id, created_at
	`
	err = s.pool.QueryRow(ctx, q,
		ra.ApplicationID, ra.RoleID, ra.PrincipalType, ra.UserID, ra.GroupID,
		ra.Effect, ra.OrganizationID, ra.IncludeChildOrgs, ra.ResourceType, ra.ResourceID,
		condBytes, ra.GrantedBy, ra.Justification, ra.StartsAt, ra.ExpiresAt,
	).Scan(&ra.ID, &ra.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create role_assignment: %w", err)
	}
	return &ra, nil
}

func (s *PostgresStore) DeleteRoleAssignment(ctx context.Context, appID, assignmentID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM role_assignments WHERE application_id = $1 AND id = $2
	`, appID, assignmentID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) ListRoleAssignmentsByApp(ctx context.Context, appID uuid.UUID) ([]domain.RoleAssignment, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, application_id, role_id, principal_type, user_id, group_id,
		       effect, organization_id, include_child_orgs, resource_type, resource_id,
		       conditions, granted_by, COALESCE(justification, ''), starts_at, expires_at, created_at
		FROM role_assignments
		WHERE application_id = $1
		ORDER BY created_at DESC
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.RoleAssignment
	for rows.Next() {
		var ra domain.RoleAssignment
		var condRaw []byte
		if err := rows.Scan(
			&ra.ID, &ra.ApplicationID, &ra.RoleID, &ra.PrincipalType, &ra.UserID, &ra.GroupID,
			&ra.Effect, &ra.OrganizationID, &ra.IncludeChildOrgs, &ra.ResourceType, &ra.ResourceID,
			&condRaw, &ra.GrantedBy, &ra.Justification, &ra.StartsAt, &ra.ExpiresAt, &ra.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(condRaw, &ra.Conditions)
		list = append(list, ra)
	}
	return list, rows.Err()
}

// ListUserActiveRolesForApp resolves baseline role slugs for inclusion in exchanged App JWTs.
func (s *PostgresStore) ListUserActiveRolesForApp(ctx context.Context, userID, appID uuid.UUID, orgID *uuid.UUID) ([]string, error) {
	const q = `
		WITH user_groups AS (
			SELECT group_id
			FROM group_memberships
			WHERE user_id = $1
			  AND (expires_at IS NULL OR expires_at > NOW())
		)
		SELECT DISTINCT r.slug
		FROM role_assignments ra
		JOIN roles r ON r.id = ra.role_id
		WHERE ra.application_id = $2
		  AND ra.effect = 'allow'
		  AND ra.resource_id IS NULL
		  AND (ra.organization_id IS NULL OR ($3::uuid IS NOT NULL AND ra.organization_id = $3))
		  AND ra.starts_at <= NOW()
		  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
		  AND (
		      (ra.principal_type = 'user' AND ra.user_id = $1)
		      OR (ra.principal_type = 'group' AND ra.group_id IN (SELECT group_id FROM user_groups))
		  )
		ORDER BY r.slug ASC
	`
	rows, err := s.pool.Query(ctx, q, userID, appID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var slug string
		if err := rows.Scan(&slug); err != nil {
			return nil, err
		}
		roles = append(roles, slug)
	}
	return roles, rows.Err()
}

// FindMatchingGrants executes the single-pass Zero Trust SQL query supporting:
// - Direct User grants & Group-inherited grants
// - Role hierarchy inheritance (WITH RECURSIVE)
// - Organization hierarchy inheritance via PostgreSQL ltree
// - Specific Resource-Instance scoping
// - Wildcard '*' resource_type or action matching
func (s *PostgresStore) FindMatchingGrants(ctx context.Context, req domain.AuthorizeRequest) ([]domain.MatchedGrant, error) {
	const q = `
		WITH RECURSIVE user_groups AS (
			SELECT group_id
			FROM group_memberships
			WHERE user_id = $1
			  AND (expires_at IS NULL OR expires_at > NOW())
		),
		requested_org AS (
			SELECT id, hierarchy_path
			FROM organizations
			WHERE id = $5 AND is_active = TRUE
		),
		matching_assignments AS (
			SELECT
				ra.id AS assignment_id,
				ra.role_id,
				ra.effect,
				ra.organization_id,
				ra.resource_type,
				ra.resource_id,
				ra.conditions AS assignment_conditions
			FROM role_assignments ra
			JOIN applications a ON a.id = ra.application_id
			LEFT JOIN organizations assigned_org ON assigned_org.id = ra.organization_id
			WHERE a.slug = $2
			  AND a.is_active = TRUE
			  AND (
			      (ra.principal_type = 'user' AND ra.user_id = $1)
			      OR (ra.principal_type = 'group' AND ra.group_id IN (SELECT group_id FROM user_groups))
			  )
			  AND ra.starts_at <= NOW()
			  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
			  AND (
			      ra.organization_id IS NULL
			      OR ($5::uuid IS NOT NULL AND ra.organization_id = $5)
			      OR (
			          $5::uuid IS NOT NULL
			          AND ra.include_child_orgs = TRUE
			          AND assigned_org.is_active = TRUE
			          AND EXISTS (
			              SELECT 1 FROM requested_org ro
			              WHERE ro.hierarchy_path <@ assigned_org.hierarchy_path
			          )
			      )
			  )
			  AND (
			      ra.resource_id IS NULL
			      OR (
			          ra.resource_id = NULLIF($6, '')
			          AND (
			              ra.resource_type IS NULL
			              OR ra.resource_type = '*'
			              OR ra.resource_type = 'distribution_system'
			              OR ra.resource_type = $3
			          )
			      )
			  )
		),
		effective_roles AS (
			SELECT
				ma.assignment_id,
				ma.effect,
				ma.organization_id,
				ma.resource_type,
				ma.resource_id,
				ma.assignment_conditions,
				r.id AS role_id,
				r.slug AS root_role_slug,
				r.inherits_from
			FROM matching_assignments ma
			JOIN roles r ON r.id = ma.role_id
			UNION ALL
			SELECT
				er.assignment_id,
				er.effect,
				er.organization_id,
				er.resource_type,
				er.resource_id,
				er.assignment_conditions,
				parent_role.id AS role_id,
				er.root_role_slug,
				parent_role.inherits_from
			FROM effective_roles er
			JOIN roles parent_role ON parent_role.id = er.inherits_from
		)
		SELECT
			er.assignment_id,
			er.effect,
			er.root_role_slug,
			p.slug AS permission_slug,
			er.organization_id,
			er.resource_type,
			er.resource_id,
			er.assignment_conditions,
			rp.conditions AS permission_conditions
		FROM effective_roles er
		JOIN role_permissions rp ON rp.role_id = er.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE (p.resource_type = $3 OR p.resource_type = '*')
		  AND (p.action = $4 OR p.action = '*')
	`

	rows, err := s.pool.Query(ctx, q,
		req.PrincipalID,
		req.AppSlug,
		req.ResourceType,
		req.Action,
		req.OrganizationID,
		req.ResourceID,
	)
	if err != nil {
		return nil, fmt.Errorf("find matching grants query: %w", err)
	}
	defer rows.Close()

	var grants []domain.MatchedGrant
	for rows.Next() {
		var g domain.MatchedGrant
		var assignCondRaw, permCondRaw []byte
		if err := rows.Scan(
			&g.AssignmentID,
			&g.Effect,
			&g.RoleSlug,
			&g.PermissionSlug,
			&g.OrganizationID,
			&g.ResourceType,
			&g.ResourceID,
			&assignCondRaw,
			&permCondRaw,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(assignCondRaw, &g.AssignmentConditions)
		_ = json.Unmarshal(permCondRaw, &g.PermissionConditions)
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

// ============================================================================
// 6. Immutable Audit Logging
// ============================================================================

func (s *PostgresStore) InsertAuditLog(ctx context.Context, entry domain.AuditLog) error {
	payloadBytes, _ := json.Marshal(entry.Payload)
	if len(payloadBytes) == 0 {
		payloadBytes = []byte("{}")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_logs (
			actor_user_id, actor_ip, application_id, event_type,
			target_type, target_id, decision, payload
		) VALUES ($1, NULLIF($2, ''), $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), $8)
	`,
		entry.ActorUserID, entry.ActorIP, entry.ApplicationID, entry.EventType,
		entry.TargetType, entry.TargetID, entry.Decision, payloadBytes,
	)
	return err
}
