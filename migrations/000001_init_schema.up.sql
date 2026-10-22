-- ============================================================================
-- Utah Common Authentication & Authorization (Zero Trust IAM / PDP)
-- Migration: 000001_init_schema.up.sql
-- Target: GCP Cloud SQL for PostgreSQL 15+
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "ltree";

-- Helper trigger function for updated_at timestamps
CREATE OR REPLACE FUNCTION trigger_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 1. IDENTITY PROVIDERS (UtahID & External OIDC Issuers)
-- ============================================================================
CREATE TYPE idp_type AS ENUM (
    'utahid',
    'gcp_identity_platform',
    'entra_id',
    'google',
    'generic_oidc'
);

CREATE TABLE identity_providers (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug                TEXT NOT NULL UNIQUE, -- e.g., 'utahid-prod', 'gcp-ext-id'
    name                TEXT NOT NULL,
    provider_type       idp_type NOT NULL,
    issuer_url          TEXT NOT NULL UNIQUE, -- OIDC 'iss' claim
    client_id           TEXT NOT NULL,        -- Expected OIDC 'aud' claim
    jwks_uri            TEXT,                 -- Optional explicit JWKS URL override
    claim_mappings      JSONB NOT NULL DEFAULT '{
        "sub": "sub",
        "email": "email",
        "name": "name",
        "groups": "groups",
        "mfa": "amr"
    }'::jsonb,
    is_internal_state   BOOLEAN NOT NULL DEFAULT FALSE, -- TRUE for state employee UtahID realm
    auto_provision      BOOLEAN NOT NULL DEFAULT TRUE,  -- Just-In-Time (JIT) user creation
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER set_identity_providers_updated_at
    BEFORE UPDATE ON identity_providers
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

-- ============================================================================
-- 2. USERS, FEDERATED IDENTITIES & GROUPS
-- ============================================================================
CREATE TYPE user_status AS ENUM (
    'active',
    'suspended',
    'pending_verification',
    'deactivated'
);

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT UNIQUE,          -- Normalized lowercase email
    email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    display_name        TEXT NOT NULL,
    user_type           TEXT NOT NULL DEFAULT 'external', -- 'state_employee', 'external_partner', 'public', 'service_account'
    status              user_status NOT NULL DEFAULT 'active',
    attributes          JSONB NOT NULL DEFAULT '{}'::jsonb, -- Agency code, division, clearance, etc.
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email_lower ON users (LOWER(email));
CREATE INDEX idx_users_attributes ON users USING GIN (attributes);

CREATE TRIGGER set_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

-- Links one or more upstream OIDC identities (UtahID, Google, Entra) to a canonical user
CREATE TABLE user_identities (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    idp_id              UUID NOT NULL REFERENCES identity_providers(id) ON DELETE RESTRICT,
    idp_subject         TEXT NOT NULL,        -- OIDC 'sub' claim from upstream IdP
    idp_email           TEXT,
    raw_claims          JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_authenticated  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (idp_id, idp_subject)
);

CREATE INDEX idx_user_identities_user_id ON user_identities(user_id);

-- ============================================================================
-- 3. ORGANIZATIONS / TENANTS (Hierarchical via ltree)
--    Represents State Agencies (DNR, DWRe), Water Districts, External Firms
-- ============================================================================
CREATE TABLE organizations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug                TEXT NOT NULL UNIQUE, -- e.g., 'utah-dnr-dwre', 'jvwcd'
    name                TEXT NOT NULL,
    org_type            TEXT NOT NULL,        -- 'state_agency', 'water_district', 'municipality', 'consultant'
    parent_id           UUID REFERENCES organizations(id) ON DELETE RESTRICT,
    hierarchy_path      LTREE NOT NULL,       -- e.g., 'state_of_utah.dnr.dwre'
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_organizations_path ON organizations USING GIST (hierarchy_path);
CREATE INDEX idx_organizations_parent ON organizations(parent_id);

CREATE TRIGGER set_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

-- Groups (can be mapped from OIDC 'groups' claims or managed per organization)
CREATE TABLE groups (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID REFERENCES organizations(id) ON DELETE CASCADE,
    slug                TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    external_idp_id     UUID REFERENCES identity_providers(id) ON DELETE SET NULL,
    external_group_id   TEXT,                 -- Upstream OIDC group claim value for auto-sync
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, slug)
);

CREATE INDEX idx_groups_external_mapping ON groups(external_idp_id, external_group_id)
    WHERE external_group_id IS NOT NULL;

CREATE TABLE group_memberships (
    group_id            UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX idx_group_memberships_user ON group_memberships(user_id);

-- ============================================================================
-- 4. APPLICATIONS & SERVICE REGISTRATION
-- ============================================================================
CREATE TABLE applications (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug                TEXT NOT NULL UNIQUE, -- Used as 'aud' claim in exchanged JWTs
    name                TEXT NOT NULL,
    description         TEXT,
    owner_org_id        UUID REFERENCES organizations(id) ON DELETE SET NULL,
    client_secret_hash  TEXT,                 -- Optional secret for backend machine-to-machine calls
    allowed_origins     TEXT[] NOT NULL DEFAULT '{}',
    token_ttl_seconds   INT NOT NULL DEFAULT 900 CHECK (token_ttl_seconds BETWEEN 60 AND 86400),
    require_mfa         BOOLEAN NOT NULL DEFAULT FALSE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER set_applications_updated_at
    BEFORE UPDATE ON applications
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

-- ============================================================================
-- 5. FINE-GRAINED PERMISSIONS & ROLES (Per Application)
-- ============================================================================
CREATE TABLE permissions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id      UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    resource_type       TEXT NOT NULL,        -- e.g., 'basin_layer', 'watershed_model', '*'
    action              TEXT NOT NULL,        -- e.g., 'read', 'write', 'delete', 'approve', '*'
    slug                TEXT GENERATED ALWAYS AS (resource_type || ':' || action) STORED,
    description         TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (application_id, resource_type, action)
);

CREATE INDEX idx_permissions_app_lookup ON permissions(application_id, resource_type, action);

CREATE TABLE roles (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id      UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    slug                TEXT NOT NULL,        -- e.g., 'hydrologist_editor', 'external_reviewer'
    name                TEXT NOT NULL,
    description         TEXT,
    is_system_role      BOOLEAN NOT NULL DEFAULT FALSE,
    inherits_from       UUID REFERENCES roles(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (application_id, slug)
);

CREATE TRIGGER set_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

-- Controls which Identity Providers can authenticate into an Application
CREATE TABLE app_identity_providers (
    application_id      UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    idp_id              UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    allow_jit_signup    BOOLEAN NOT NULL DEFAULT FALSE,
    default_role_id     UUID REFERENCES roles(id) ON DELETE SET NULL,
    PRIMARY KEY (application_id, idp_id)
);

CREATE TABLE role_permissions (
    role_id             UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id       UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    conditions          JSONB NOT NULL DEFAULT '{}'::jsonb, -- Optional ABAC condition on this permission
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

-- ============================================================================
-- 6. SCOPED ROLE ASSIGNMENTS (Zero Trust Policy Core)
-- ============================================================================
CREATE TYPE grant_effect AS ENUM ('allow', 'deny');
CREATE TYPE principal_type AS ENUM ('user', 'group');

CREATE TABLE role_assignments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id      UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    role_id             UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,

    -- Who receives the grant (User or Group)
    principal_type      principal_type NOT NULL,
    user_id             UUID REFERENCES users(id) ON DELETE CASCADE,
    group_id            UUID REFERENCES groups(id) ON DELETE CASCADE,

    -- Allow or Explicit Deny (Explicit Deny always wins in Zero Trust evaluation)
    effect              grant_effect NOT NULL DEFAULT 'allow',

    -- Scoping:
    -- 1. Global to App: organization_id IS NULL AND resource_id IS NULL
    -- 2. Tenant/Org Scoped: organization_id IS NOT NULL (with optional child org inheritance)
    -- 3. Resource Instance Scoped: resource_type IS NOT NULL AND resource_id IS NOT NULL
    organization_id     UUID REFERENCES organizations(id) ON DELETE CASCADE,
    include_child_orgs  BOOLEAN NOT NULL DEFAULT TRUE,
    resource_type       TEXT,                 -- e.g., 'basin', 'project', 'water_right'
    resource_id         TEXT,                 -- e.g., 'bear-river', 'utah-lake', 'wr-44102'

    -- Zero Trust ABAC Conditions & Time-bound Access
    conditions          JSONB NOT NULL DEFAULT '{}'::jsonb, -- e.g., {"ip_cidrs": ["204.113.0.0/16"], "require_mfa": true}
    granted_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    justification       TEXT,
    starts_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ,          -- Enforces temporary access for external contractors
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_principal_xor CHECK (
        (principal_type = 'user' AND user_id IS NOT NULL AND group_id IS NULL) OR
        (principal_type = 'group' AND group_id IS NOT NULL AND user_id IS NULL)
    ),
    CONSTRAINT chk_resource_pair CHECK (
        resource_type IS NULL OR resource_id IS NOT NULL
    )
);

CREATE INDEX idx_role_assignments_user_lookup
    ON role_assignments(application_id, user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_role_assignments_group_lookup
    ON role_assignments(application_id, group_id) WHERE group_id IS NOT NULL;
CREATE INDEX idx_role_assignments_resource_lookup
    ON role_assignments(application_id, resource_type, resource_id) WHERE resource_id IS NOT NULL;
CREATE INDEX idx_role_assignments_org_lookup
    ON role_assignments(application_id, organization_id) WHERE organization_id IS NOT NULL;

-- ============================================================================
-- 7. IMMUTABLE AUDIT LOGS (Admin Mutations & Zero Trust Access Decisions)
-- ============================================================================
CREATE TABLE audit_logs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_time          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_ip            TEXT,
    application_id      UUID REFERENCES applications(id) ON DELETE SET NULL,
    event_type          TEXT NOT NULL,        -- e.g., 'admin.role.created', 'authz.check', 'authn.token_exchange'
    target_type         TEXT,
    target_id           TEXT,
    decision            TEXT,                 -- 'allow', 'deny', 'error'
    payload             JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_audit_logs_time ON audit_logs(event_time DESC);
CREATE INDEX idx_audit_logs_app_event ON audit_logs(application_id, event_type, event_time DESC);
