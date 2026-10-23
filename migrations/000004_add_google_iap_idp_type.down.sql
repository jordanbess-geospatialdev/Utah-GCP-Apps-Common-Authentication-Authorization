-- ============================================================================
-- Migration: 000004_add_google_iap_idp_type.down.sql
-- PostgreSQL does not support removing an enum value (ALTER TYPE ... DROP VALUE),
-- so this downgrade is intentionally a no-op; 'google_iap' is harmless if unused.
-- ============================================================================

-- no-op
