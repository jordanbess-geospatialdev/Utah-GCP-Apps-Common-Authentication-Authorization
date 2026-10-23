-- ============================================================================
-- Migration: 000004_add_google_iap_idp_type.up.sql
-- Adds the 'google_iap' provider type for Google Cloud Identity-Aware Proxy.
-- Split from the seed migration in 000005 so transactional runners (e.g. golang-migrate)
-- never use a newly added enum value inside the same transaction that created it.
-- ============================================================================

ALTER TYPE idp_type ADD VALUE IF NOT EXISTS 'google_iap';
