-- ============================================================================
-- Migration: 000001_init_schema.down.sql
-- ============================================================================

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS role_assignments;
DROP TYPE IF EXISTS principal_type;
DROP TYPE IF EXISTS grant_effect;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS app_identity_providers;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS group_memberships;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS user_identities;
DROP TABLE IF EXISTS users;
DROP TYPE IF EXISTS user_status;
DROP TABLE IF EXISTS identity_providers;
DROP TYPE IF EXISTS idp_type;
DROP FUNCTION IF EXISTS trigger_set_updated_at();
