-- ============================================================================
-- Migration: 000002_seed_utah_defaults.down.sql
-- ============================================================================

DELETE FROM applications WHERE slug IN ('utah-iam-admin', 'water-resources-map');
DELETE FROM organizations WHERE slug IN ('utah-dnr-dwre', 'utah-dnr', 'state-of-utah', 'jvwcd', 'cuwcd');
DELETE FROM identity_providers WHERE slug IN ('utahid-prod', 'external-gcp-identity');
