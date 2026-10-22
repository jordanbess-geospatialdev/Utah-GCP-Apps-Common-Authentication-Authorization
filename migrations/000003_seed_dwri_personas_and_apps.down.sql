-- ============================================================================
-- Migration: 000003_seed_dwri_personas_and_apps.down.sql
-- ============================================================================

DELETE FROM applications WHERE slug IN (
    'dwri-water-measurement-dashboard',
    'dwri-wcat',
    'dwri-water-use-program',
    'dwri-water-rights-core'
);

DELETE FROM groups WHERE slug IN (
    'dwri-regional-office-staff',
    'dwri-well-drilling-staff',
    'dwri-maillog-staff',
    'dwri-water-right-entry-editors'
);

DELETE FROM organizations WHERE slug IN (
    'dwri-region-northern-logan',
    'dwri-region-weber-ogden',
    'dwri-region-utah-lake-jordan',
    'dwri-region-vernal',
    'dwri-region-southeastern-price',
    'dwri-region-sevier-richfield',
    'dwri-region-southern-cedar',
    'utah-dnr-dwri',
    'usgs-utah-water-science',
    'crau',
    'prwua'
);

DELETE FROM identity_providers WHERE slug = 'research-orcid-oidc';
