-- ============================================================================
-- Migration: 000005_seed_google_iap_idp.up.sql
-- Seeds the Google Cloud Identity-Aware Proxy (IAP) Identity Provider.
--
-- IAP signs a JWT assertion on every request (header 'x-goog-iap-jwt-assertion') with:
--   iss = https://cloud.google.com/iap
--   aud = /projects/PROJECT_NUMBER/locations/REGION/services/SERVICE_NAME   (Cloud Run)
--   keys = https://www.gstatic.com/iap/verify/public_key-jwk               (ES256 JWKS)
--
-- The row is seeded INACTIVE with a placeholder audience: enable it by setting client_id to
-- your real IAP signed-header audience (comma-separated list when several IAP-protected
-- services share this issuer) and flipping is_active to TRUE. See docs/IAP_INTEGRATION.md.
-- ============================================================================

INSERT INTO identity_providers (
    id, slug, name, provider_type, issuer_url, client_id, jwks_uri,
    is_internal_state, auto_provision, is_active, claim_mappings
) VALUES
(
    '11111111-1111-4111-8111-111111111103',
    'google-iap',
    'Google Cloud Identity-Aware Proxy (IAP)',
    'google_iap',
    'https://cloud.google.com/iap',
    'REPLACE_WITH_IAP_JWT_AUDIENCE',
    'https://www.gstatic.com/iap/verify/public_key-jwk',
    FALSE,
    TRUE,
    FALSE,
    '{"sub": "sub", "email": "email", "name": "email", "groups": "groups", "mfa": "amr"}'::jsonb
)
ON CONFLICT (slug) DO NOTHING;
