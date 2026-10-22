-- ============================================================================
-- Migration: 000002_seed_utah_defaults.up.sql
-- Seeds default Identity Providers (UtahID + External), Organizations (DNR/DWRe),
-- the IAM Admin App, and the Utah Water Resources Map Application.
-- ============================================================================

-- 1. Seed Identity Providers
INSERT INTO identity_providers (
    id, slug, name, provider_type, issuer_url, client_id, is_internal_state, auto_provision, claim_mappings
) VALUES
(
    '11111111-1111-4111-8111-111111111101',
    'utahid-prod',
    'State of Utah (UtahID OIDC)',
    'utahid',
    'https://id.utah.gov/oauth2/default',
    'utah-dnr-common-auth-client',
    TRUE,
    TRUE,
    '{"sub": "sub", "email": "email", "name": "name", "groups": "groups", "mfa": "amr", "agency": "utah_agency"}'::jsonb
),
(
    '11111111-1111-4111-8111-111111111102',
    'external-gcp-identity',
    'External Collaborators (GCP Identity Platform / Federated OIDC)',
    'gcp_identity_platform',
    'https://securetoken.google.com/utah-water-external-auth',
    'utah-water-external-auth',
    FALSE,
    TRUE,
    '{"sub": "sub", "email": "email", "name": "name", "groups": "groups", "mfa": "firebase.sign_in_second_factor"}'::jsonb
)
ON CONFLICT (slug) DO NOTHING;

-- 2. Seed Hierarchical Organizations (State Agencies & External Water Districts)
INSERT INTO organizations (id, slug, name, org_type, parent_id, hierarchy_path) VALUES
(
    '22222222-2222-4222-8222-222222222201',
    'state-of-utah',
    'State of Utah',
    'state_agency',
    NULL,
    'state_of_utah'
),
(
    '22222222-2222-4222-8222-222222222202',
    'utah-dnr',
    'Utah Department of Natural Resources (DNR)',
    'state_agency',
    '22222222-2222-4222-8222-222222222201',
    'state_of_utah.dnr'
),
(
    '22222222-2222-4222-8222-222222222203',
    'utah-dnr-dwre',
    'Utah Division of Water Resources (DWRe)',
    'state_agency',
    '22222222-2222-4222-8222-222222222202',
    'state_of_utah.dnr.dwre'
),
(
    '22222222-2222-4222-8222-222222222204',
    'jvwcd',
    'Jordan Valley Water Conservancy District',
    'water_district',
    NULL,
    'external_orgs.jvwcd'
),
(
    '22222222-2222-4222-8222-222222222205',
    'cuwcd',
    'Central Utah Water Conservancy District',
    'water_district',
    NULL,
    'external_orgs.cuwcd'
)
ON CONFLICT (slug) DO NOTHING;

-- 3. Seed Core Applications
INSERT INTO applications (
    id, slug, name, description, owner_org_id, token_ttl_seconds, require_mfa
) VALUES
(
    '33333333-3333-4333-8333-333333333301',
    'utah-iam-admin',
    'Utah Common IAM & Policy Administration Service',
    'Control plane for registering applications, roles, permissions, and Zero Trust policies.',
    '22222222-2222-4222-8222-222222222203',
    600,
    TRUE
),
(
    '33333333-3333-4333-8333-333333333302',
    'water-resources-map',
    'Utah Water Resources GIS & Basin Planning Application',
    'Interactive spatial water resources, basin modeling, and water district planning portal.',
    '22222222-2222-4222-8222-222222222203',
    900,
    FALSE
)
ON CONFLICT (slug) DO NOTHING;

-- 4. Seed Permissions for 'utah-iam-admin' & 'water-resources-map'
INSERT INTO permissions (id, application_id, resource_type, action, description) VALUES
-- IAM Admin permissions
('44444444-4444-4444-8444-444444444401', '33333333-3333-4333-8333-333333333301', '*', '*', 'Full super-admin control over IAM'),
('44444444-4444-4444-8444-444444444402', '33333333-3333-4333-8333-333333333301', 'application', 'manage', 'Register and configure applications and roles'),
('44444444-4444-4444-8444-444444444403', '33333333-3333-4333-8333-333333333301', 'assignment', 'manage', 'Grant and revoke role assignments'),
-- Water Resources Map permissions
('44444444-4444-4444-8444-444444444410', '33333333-3333-4333-8333-333333333302', 'basin_layer', 'read', 'View hydrologic basin GIS layers'),
('44444444-4444-4444-8444-444444444411', '33333333-3333-4333-8333-333333333302', 'basin_layer', 'write', 'Edit and publish hydrologic basin GIS layers'),
('44444444-4444-4444-8444-444444444412', '33333333-3333-4333-8333-333333333302', 'watershed_model', 'run', 'Execute watershed simulation scenarios'),
('44444444-4444-4444-8444-444444444413', '33333333-3333-4333-8333-333333333302', 'watershed_model', 'approve', 'Approve official state watershed models'),
('44444444-4444-4444-8444-444444444414', '33333333-3333-4333-8333-333333333302', 'water_district_submission', 'submit', 'Submit water conservation & demand data for a district'),
('44444444-4444-4444-8444-444444444415', '33333333-3333-4333-8333-333333333302', 'sensitive_infrastructure', 'read', 'View critical dam/aqueduct infrastructure layers')
ON CONFLICT (application_id, resource_type, action) DO NOTHING;

-- 5. Seed Roles
INSERT INTO roles (id, application_id, slug, name, description, is_system_role) VALUES
('55555555-5555-4555-8555-555555555501', '33333333-3333-4333-8333-333333333301', 'iam_super_admin', 'IAM Super Administrator', 'Full administrative control over all IAM entities', TRUE),
('55555555-5555-4555-8555-555555555510', '33333333-3333-4333-8333-333333333302', 'dwre_hydrologist', 'DWRe State Hydrologist', 'State employee role with full basin editing and model execution', TRUE),
('55555555-5555-4555-8555-555555555511', '33333333-3333-4333-8333-333333333302', 'external_district_engineer', 'External Water District Collaborator', 'External partner role for viewing basins, running models, and submitting district data', FALSE),
('55555555-5555-4555-8555-555555555512', '33333333-3333-4333-8333-333333333302', 'public_viewer', 'Public Map Viewer', 'Read-only access to public basin layers', TRUE)
ON CONFLICT (application_id, slug) DO NOTHING;

-- 6. Bind Permissions to Roles
INSERT INTO role_permissions (role_id, permission_id, conditions) VALUES
-- IAM Super Admin
('55555555-5555-4555-8555-555555555501', '44444444-4444-4444-8444-444444444401', '{"require_mfa": true}'::jsonb),
-- DWRe State Hydrologist
('55555555-5555-4555-8555-555555555510', '44444444-4444-4444-8444-444444444410', '{}'::jsonb),
('55555555-5555-4555-8555-555555555510', '44444444-4444-4444-8444-444444444411', '{}'::jsonb),
('55555555-5555-4555-8555-555555555510', '44444444-4444-4444-8444-444444444412', '{}'::jsonb),
('55555555-5555-4555-8555-555555555510', '44444444-4444-4444-8444-444444444413', '{"require_mfa": true}'::jsonb),
('55555555-5555-4555-8555-555555555510', '44444444-4444-4444-8444-444444444415', '{"require_mfa": true}'::jsonb),
-- External Water District Collaborator
('55555555-5555-4555-8555-555555555511', '44444444-4444-4444-8444-444444444410', '{}'::jsonb),
('55555555-5555-4555-8555-555555555511', '44444444-4444-4444-8444-444444444412', '{}'::jsonb),
('55555555-5555-4555-8555-555555555511', '44444444-4444-4444-8444-444444444414', '{}'::jsonb),
-- Public Viewer
('55555555-5555-4555-8555-555555555512', '44444444-4444-4444-8444-444444444410', '{}'::jsonb)
ON CONFLICT DO NOTHING;

-- 7. Bind Allowed Identity Providers to Applications
INSERT INTO app_identity_providers (application_id, idp_id, allow_jit_signup, default_role_id) VALUES
-- IAM Admin only trusts internal State UtahID
('33333333-3333-4333-8333-333333333301', '11111111-1111-4111-8111-111111111101', FALSE, NULL),
-- Water Resources Map trusts both UtahID and External Collaborator IdP (defaulting JIT users to public_viewer)
('33333333-3333-4333-8333-333333333302', '11111111-1111-4111-8111-111111111101', TRUE, '55555555-5555-4555-8555-555555555512'),
('33333333-3333-4333-8333-333333333302', '11111111-1111-4111-8111-111111111102', TRUE, '55555555-5555-4555-8555-555555555512')
ON CONFLICT DO NOTHING;
