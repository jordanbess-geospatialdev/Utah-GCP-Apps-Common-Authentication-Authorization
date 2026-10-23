-- ============================================================================
-- Migration: 000005_seed_google_iap_idp.down.sql
-- ============================================================================

DELETE FROM app_identity_providers WHERE idp_id IN (SELECT id FROM identity_providers WHERE slug = 'google-iap');
DELETE FROM identity_providers WHERE slug = 'google-iap';
