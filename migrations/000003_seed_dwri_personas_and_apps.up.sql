-- ============================================================================
-- Migration: 000003_seed_dwri_personas_and_apps.up.sql
-- Configures the Utah Division of Water Rights (DWRi) 2026 Water Measurement
-- Dashboard (6 Personas + Sub-Personas from the 72-page Sep 2026 UCD PDF &
-- Figma prototypes) AND maps the 4 legacy permission stores (wrsysDB, WCAT,
-- DVRTEDIT, Water Use Program, HydroServer) into Zero Trust RBAC + ABAC.
-- ============================================================================

-- 1. Additional External OIDC Identity Provider for Scientists/Researchers (Sarah Persona)
INSERT INTO identity_providers (
    id, slug, name, provider_type, issuer_url, client_id, is_internal_state, auto_provision, claim_mappings
) VALUES (
    '11111111-1111-4111-8111-111111111103',
    'research-orcid-oidc',
    'Research & Multi-Agency Federated OIDC (ORCID / USGS / USU / BOR / CRAU)',
    'generic_oidc',
    'https://orcid.org',
    'utah-dwri-research-portal',
    FALSE,
    TRUE,
    '{"sub": "sub", "email": "email", "name": "name", "groups": "groups", "mfa": "amr"}'::jsonb
)
ON CONFLICT (slug) DO NOTHING;

-- 2. DWRi Hierarchical Organizations (ltree)
--    Models DWRi Headquarters, the 6 Sections & 7 Regional Offices (PDF p. 2:
--    Logan, Salt Lake City [2], Vernal, Price, Richfield, Cedar City),
--    plus External Partner Agencies (USGS, CRAU, USU) and Public Water Suppliers.
INSERT INTO organizations (id, slug, name, org_type, parent_id, hierarchy_path) VALUES
(
    '22222222-2222-4222-8222-222222222210',
    'utah-dnr-dwri',
    'Utah Division of Water Rights (DWRi - Office of the State Engineer)',
    'state_agency',
    '22222222-2222-4222-8222-222222222202',
    'state_of_utah.dnr.dwri'
),
(
    '22222222-2222-4222-8222-222222222211',
    'dwri-region-northern-logan',
    'DWRi Northern Regional Office (Logan)',
    'state_agency',
    '22222222-2222-4222-8222-222222222210',
    'state_of_utah.dnr.dwri.region_northern_logan'
),
(
    '22222222-2222-4222-8222-222222222212',
    'dwri-region-weber-ogden',
    'DWRi Weber / Ogden Regional Office (Salt Lake City)',
    'state_agency',
    '22222222-2222-4222-8222-222222222210',
    'state_of_utah.dnr.dwri.region_weber_ogden'
),
(
    '22222222-2222-4222-8222-222222222213',
    'dwri-region-utah-lake-jordan',
    'DWRi Utah Lake / Jordan River Regional Office (Salt Lake City)',
    'state_agency',
    '22222222-2222-4222-8222-222222222210',
    'state_of_utah.dnr.dwri.region_utah_lake_jordan'
),
(
    '22222222-2222-4222-8222-222222222214',
    'dwri-region-vernal',
    'DWRi Uinta Basin Regional Office (Vernal)',
    'state_agency',
    '22222222-2222-4222-8222-222222222210',
    'state_of_utah.dnr.dwri.region_vernal'
),
(
    '22222222-2222-4222-8222-222222222215',
    'dwri-region-southeastern-price',
    'DWRi Southeastern Regional Office (Price)',
    'state_agency',
    '22222222-2222-4222-8222-222222222210',
    'state_of_utah.dnr.dwri.region_southeastern_price'
),
(
    '22222222-2222-4222-8222-222222222216',
    'dwri-region-sevier-richfield',
    'DWRi Sevier River Regional Office (Richfield)',
    'state_agency',
    '22222222-2222-4222-8222-222222222210',
    'state_of_utah.dnr.dwri.region_sevier_richfield'
),
(
    '22222222-2222-4222-8222-222222222217',
    'dwri-region-southern-cedar',
    'DWRi Southern Regional Office (Cedar City)',
    'state_agency',
    '22222222-2222-4222-8222-222222222210',
    'state_of_utah.dnr.dwri.region_southern_cedar'
),
(
    '22222222-2222-4222-8222-222222222220',
    'usgs-utah-water-science',
    'USGS Utah Water Science Center (External Federal Partner)',
    'consultant',
    NULL,
    'external_orgs.federal.usgs_utah'
),
(
    '22222222-2222-4222-8222-222222222221',
    'crau',
    'Colorado River Authority of Utah (CRAU)',
    'state_agency',
    '22222222-2222-4222-8222-222222222201',
    'state_of_utah.crau'
),
(
    '22222222-2222-4222-8222-222222222222',
    'prwua',
    'Provo River Water Users Association (PRWUA)',
    'water_district',
    NULL,
    'external_orgs.prwua'
)
ON CONFLICT (slug) DO NOTHING;

-- 3. Job-Based Groups (Replaces wrsysDB's "Repeated Role Sets" granted 1 row at a time)
INSERT INTO groups (id, organization_id, slug, name, description) VALUES
(
    '66666666-6666-4666-8666-666666666601',
    '22222222-2222-4222-8222-222222222210',
    'dwri-regional-office-staff',
    'DWRi Regional Office Staff',
    'Replaces the 101 individual wrsysDB grants shared across Regional Office staff (wrEntry, Memovision, ProofTracker RegOffice, Designate)'
),
(
    '66666666-6666-4666-8666-666666666602',
    '22222222-2222-4222-8222-222222222210',
    'dwri-well-drilling-staff',
    'DWRi Well Drilling & Dam Safety Staff',
    'Consolidates the 18 staff members holding WellDrilling, StartCards, and DamSafety roles'
),
(
    '66666666-6666-4666-8666-666666666603',
    '22222222-2222-4222-8222-222222222210',
    'dwri-maillog-staff',
    'DWRi MailLog & Records Staff',
    'Consolidates the 11 MailLog staff accounts'
),
(
    '66666666-6666-4666-8666-666666666604',
    '22222222-2222-4222-8222-222222222210',
    'dwri-water-right-entry-editors',
    'DWRi Water Right Entry Editors',
    'Consolidates the 5 wrEntry Editor / Editor_Advanced / Editor_Owner specialists'
)
ON CONFLICT (organization_id, slug) DO NOTHING;

-- 4. Register DWRi Applications
INSERT INTO applications (
    id, slug, name, description, owner_org_id, token_ttl_seconds, require_mfa
) VALUES
(
    '33333333-3333-4333-8333-333333333310',
    'dwri-water-measurement-dashboard',
    'DWRi Next-Gen Water Measurement Data Dashboard (2026 Unified Platform)',
    'Unified GeoLibre/MapLibre + NeoServer dashboard replacing fragmented HydroServer, DVRTEDIT, and WCAT measurement workflows for all 6 DWRi personas.',
    '22222222-2222-4222-8222-222222222210',
    900,
    FALSE
),
(
    '33333333-3333-4333-8333-333333333311',
    'dwri-wcat',
    'DWRi Water Commissioner Accounting Tool (WCAT)',
    'Distribution system accounting & priority classes (replaces 62 hardcoded system role names with resource_id scoping).',
    '22222222-2222-4222-8222-222222222210',
    900,
    FALSE
),
(
    '33333333-3333-4333-8333-333333333312',
    'dwri-water-use-program',
    'DWRi Water Use & Public Water Supplier Reporting Program',
    'Water supplier system inventories, industrial water use, boundary proposals, and annual supplier reporting (Parker & Diego Water Use Manager personas).',
    '22222222-2222-4222-8222-222222222210',
    900,
    FALSE
),
(
    '33333333-3333-4333-8333-333333333313',
    'dwri-water-rights-core',
    'DWRi Water Rights Core Suite (wrEntry, AppTracker, ProofTracker, WellDrilling)',
    'Modernized FastAPI/React water rights adjudication, applications, well drilling, and document workflows.',
    '22222222-2222-4222-8222-222222222210',
    900,
    FALSE
)
ON CONFLICT (slug) DO NOTHING;

-- ============================================================================
-- 5. Fine-Grained Permissions for 'dwri-water-measurement-dashboard'
--    Directly mapped to the 72-page Sep 2026 UCD PDF & Figma Mockups
-- ============================================================================
INSERT INTO permissions (id, application_id, resource_type, action, description) VALUES
-- 1. Donna (Public, Director, Auditor, Legislator — PDF pp. 57-65, Figma node 81-365)
('44444444-4444-4444-8444-444444444501', '33333333-3333-4333-8333-333333333310', 'published_station', 'read', 'Browse published stations, time series, FAIR data dictionary, and legislative KPI scorecards (FR-001..FR-008, FR-058..FR-062)'),
('44444444-4444-4444-8444-444444444502', '33333333-3333-4333-8333-333333333310', 'public_export', 'create', 'Download single-site or multi-site CSV series and dynamic basin summaries (FR-063)'),
-- 2. Wiley & Parker (Water User & Public Water Supplier — PDF pp. 52-56, Figma node 1193-1908)
('44444444-4444-4444-8444-444444444503', '33333333-3333-4333-8333-333333333310', 'user_preference', 'manage_own', 'Access My Sites tab, favorite distribution sites, and configure personal alert notifications (FR-009, FR-052)'),
('44444444-4444-4444-8444-444444444504', '33333333-3333-4333-8333-333333333310', 'supplier_system', 'read', 'Access My System portal for assigned water area: view sources, purchases, wholesale, and returns (FR-053, PDF p. 55)'),
('44444444-4444-4444-8444-444444444505', '33333333-3333-4333-8333-333333333310', 'supplier_boundary', 'propose', 'Propose boundary area changes with comments and download boundary files (FR-054, PDF p. 55)'),
('44444444-4444-4444-8444-444444444506', '33333333-3333-4333-8333-333333333310', 'supplier_report', 'submit', 'Enter/import culinary, source, purchase, wholesale, returns, peak demand & secondary water use and submit annual PDF report (FR-055..FR-057, PDF p. 56)'),
-- 3. Sarah (Scientist, Researcher, Consultant — PDF pp. 66-70, Figma node 1601-13148)
('44444444-4444-4444-8444-444444444507', '33333333-3333-4333-8333-333333333310', 'research_dataset', 'read', 'Programmatic API query across processing levels (raw, provisional at time of distribution, best-available) & qualifiers (FR-065, FR-066, PDF p. 68)'),
('44444444-4444-4444-8444-444444444508', '33333333-3333-4333-8333-333333333310', 'api_token', 'manage_own', 'Generate, rotate, and revoke personal programmatic API tokens without creating a new account (FR-064, PDF p. 67)'),
-- 4. Cody (Water Commissioner & Deputy — PDF pp. 23-35, Figma node 1193-1908)
('44444444-4444-4444-8444-444444444510', '33333333-3333-4333-8333-333333333310', 'distribution_system', 'read_restricted', 'View Manage tab for assigned distribution system sites and water deliveries to users (FR-019, PDF p. 31)'),
('44444444-4444-4444-8444-444444444511', '33333333-3333-4333-8333-333333333310', 'measurement', 'create', 'Enter manual observations, mobile/offline field drafts, and 366-day Excel spreadsheet block paste (FR-020, FR-021, FR-027, PDF pp. 31-34)'),
('44444444-4444-4444-8444-444444444512', '33333333-3333-4333-8333-333333333310', 'measurement', 'revise', 'Correct provisional/best-available time series with qualifiers (interpolate, ice-affected) and justification (FR-022, FR-040..FR-042, PDF p. 32)'),
('44444444-4444-4444-8444-444444444513', '33333333-3333-4333-8333-333333333310', 'station', 'update_assigned', 'Edit permitted station details (name, location, elevation, min/max capacities, public photos) with audit trail (FR-023, PDF p. 33)'),
('44444444-4444-4444-8444-444444444514', '33333333-3333-4333-8333-333333333310', 'distribution_report', 'generate', 'Generate annual distribution report summarizing daily flow, volume, apportionments, and estimates (FR-024, PDF pp. 33-35)'),
-- 5. Fatima (Field, Distribution, Automation, Regional, & Modeling Engineers — PDF pp. 36-51, Table 2 p. 38, Figma node 545-8730)
('44444444-4444-4444-8444-444444444520', '33333333-3333-4333-8333-333333333310', 'station', 'create', 'Create new sites, groups/subgroups, and effective-dated datastreams when device setup changes (FR-031..FR-034, PDF p. 40)'),
('44444444-4444-4444-8444-444444444521', '33333333-3333-4333-8333-333333333310', 'diagnostics', 'read', 'View engineering diagnostics including battery voltage, sensor health, and known data issues (FR-036, FR-038, PDF p. 41)'),
('44444444-4444-4444-8444-444444444522', '33333333-3333-4333-8333-333333333310', 'site_visit', 'manage', 'Record field visits, voice-to-text notes, rating curve regressions, and data shifts (FR-045..FR-047, PDF pp. 43-44)'),
('44444444-4444-4444-8444-444444444523', '33333333-3333-4333-8333-333333333310', 'attachment_internal', 'manage', 'Upload and view internal-only photos and notes (wiring details, gate codes, key numbers, serial number tags) (FR-049, PDF p. 45)'),
('44444444-4444-4444-8444-444444444524', '33333333-3333-4333-8333-333333333310', 'raw_observation', 'withdraw', 'Automation Engineer only: delete/withdraw erroneous raw readings (e.g., sensor out of water) with audit record (FR-039, PDF p. 42)'),
('44444444-4444-4444-8444-444444444525', '33333333-3333-4333-8333-333333333310', 'ingestion_connection', 'request', 'Configure staging orchestrator scraping frequency and custom satellite variable headers (FR-013, PDF pp. 40, 49)'),
('44444444-4444-4444-8444-444444444526', '33333333-3333-4333-8333-333333333310', 'wcat_model', 'sync', 'Synchronize WCAT accounting models, ROCS notifications, and water-right-network links (FR-051, PDF pp. 38, 47, 50)'),
('44444444-4444-4444-8444-444444444527', '33333333-3333-4333-8333-333333333310', 'asset_inventory', 'manage', 'Scan, verify, and transfer field measurement equipment assets across stations (FR-048, PDF pp. 44, 47, 49)'),
('44444444-4444-4444-8444-444444444528', '33333333-3333-4333-8333-333333333310', 'telemetry_address', 'manage', 'View and edit sensitive Cell IP/Port, Radio Addresses, Pakbus security, and peripheral card addresses (FR-050, PDF pp. 47, 49)'),
('44444444-4444-4444-8444-444444444529', '33333333-3333-4333-8333-333333333310', 'enforcement', 'assist', 'Regional Engineer: assist with water distribution outside established systems and water right enforcement (PDF p. 38 Table 2)'),
-- 6. Diego (Data Steward / QA-QC Manager & Water Use Program Data Manager — PDF pp. 17-22, Figma node 173-1356)
('44444444-4444-4444-8444-444444444530', '33333333-3333-4333-8333-333333333310', 'vocabulary', 'manage', 'Sole authority to create/delete distribution systems and edit universal metadata (sensors, properties, levels, units, qualifiers) (FR-012, PDF p. 19)'),
('44444444-4444-4444-8444-444444444531', '33333333-3333-4333-8333-333333333310', 'ingestion_connection', 'manage', 'Set up production orchestrator data providers and monitor overall connections health digest (FR-013, FR-014, PDF p. 19)'),
('44444444-4444-4444-8444-444444444532', '33333333-3333-4333-8333-333333333310', 'qc_rule', 'manage', 'Configure automated QC thresholds (range, voltage, rate-of-change, persistence, missing, zero) and promote to prod (FR-015, PDF p. 20)'),
('44444444-4444-4444-8444-444444444533', '33333333-3333-4333-8333-333333333310', 'user_assignment', 'manage', 'Manage users and assign Distribution Engineers, Commissioners, and Deputies to systems/sites (FR-011, PDF p. 18)'),
('44444444-4444-4444-8444-444444444534', '33333333-3333-4333-8333-333333333310', 'supplier_system', 'manage_review', 'Water Use Program Data Manager: access Manage Systems dashboard, review submitted supplier reports, view all boundary categories (PDF pp. 21-22)')
ON CONFLICT (application_id, resource_type, action) DO NOTHING;

-- ============================================================================
-- 6. Persona & Sub-Persona Roles for 'dwri-water-measurement-dashboard'
-- ============================================================================
INSERT INTO roles (id, application_id, slug, name, description, is_system_role, inherits_from) VALUES
(
    '55555555-5555-4555-8555-555555555601',
    '33333333-3333-4333-8333-333333333310',
    'donna_public_reader',
    'Public Reader, Director, Auditor & Legislator (Donna Persona)',
    'No-login or basic read access to published stations, FAIR data dictionary, legislative KPIs, and CSV exports (Figma node 81-365).',
    TRUE,
    NULL
),
(
    '55555555-5555-4555-8555-555555555602',
    '33333333-3333-4333-8333-333333333310',
    'wiley_water_user',
    'Registered Water User (Wiley Persona / Authenticated Donna)',
    'Default role granted on JIT account creation (PDF p. 58); adds My Sites favorites and personal alert notifications (Figma node 1193-1908).',
    TRUE,
    '55555555-5555-4555-8555-555555555601'
),
(
    '55555555-5555-4555-8555-555555555603',
    '33333333-3333-4333-8333-333333333310',
    'parker_water_supplier',
    'Public Water Supplier Representative (Parker / Wiley R2 Persona)',
    'Scoped to a specific Water Supplier organization (e.g. JVWCD, CUWCD, PRWUA, City) for My System inventory, boundary proposals, and annual Water Use Reports (PDF pp. 54-56).',
    FALSE,
    '55555555-5555-4555-8555-555555555602'
),
(
    '55555555-5555-4555-8555-555555555604',
    '33333333-3333-4333-8333-333333333310',
    'sarah_researcher',
    'Scientist, Researcher & Consultant (Sarah Persona)',
    'Programmatic REST API access, personal API token rotation/revocation, provisional vs. best-available filtering, and bulk exports (Figma node 1601-13148).',
    FALSE,
    '55555555-5555-4555-8555-555555555602'
),
(
    '55555555-5555-4555-8555-555555555605',
    '33333333-3333-4333-8333-333333333310',
    'cody_commissioner',
    'Water Commissioner & Deputy (Cody Persona)',
    'Scoped to assigned distribution_system (or time-bounded for Deputies) for mobile/spreadsheet entry, provisional review, site metadata edits, and annual reports (Figma node 1193-1908).',
    FALSE,
    '55555555-5555-4555-8555-555555555602'
),
(
    '55555555-5555-4555-8555-555555555606',
    '33333333-3333-4333-8333-333333333310',
    'fatima_distribution_engineer',
    'Distribution Engineer (Fatima / Dory Persona — PDF p. 38 Table 2)',
    'Oversees water distribution, trains Commissioners, creates sites/datastreams, views battery voltage diagnostics, logs rating curve shifts, and uploads internal photos (Figma node 545-8730).',
    FALSE,
    '55555555-5555-4555-8555-555555555605'
),
(
    '55555555-5555-4555-8555-555555555607',
    '33333333-3333-4333-8333-333333333310',
    'fatima_automation_engineer',
    'Automation & Telemetry Engineer (Fatima Automation Profile — PDF p. 38 Table 2)',
    'Extends Distribution Engineer with raw observation withdrawal/deletion, telemetry IP/Pakbus security addresses, asset inventory scanning, and staging orchestrator setup.',
    FALSE,
    '55555555-5555-4555-8555-555555555606'
),
(
    '55555555-5555-4555-8555-555555555608',
    '33333333-3333-4333-8333-333333333310',
    'fatima_modeling_engineer',
    'Water Rights Engineer - Modeling (Fatima Modeler Profile — PDF p. 38 Table 2)',
    'Creates and syncs WCAT river models and inspects diagnostics without station hardware, Pakbus security, or raw-deletion privileges.',
    FALSE,
    '55555555-5555-4555-8555-555555555604'
),
(
    '55555555-5555-4555-8555-555555555612',
    '33333333-3333-4333-8333-333333333310',
    'fatima_regional_engineer',
    'Regional Office Engineer (Fatima Regional Profile — PDF p. 38 Table 2)',
    'Scoped to one of the 7 DWRi Regional Offices (ltree) to supervise regional distribution systems, operate river models, and assist with water right enforcement.',
    FALSE,
    '55555555-5555-4555-8555-555555555606'
),
(
    '55555555-5555-4555-8555-555555555609',
    '33333333-3333-4333-8333-333333333310',
    'diego_data_steward',
    'Statewide Data Steward & QA/QC Manager (Diego Persona — Figma node 173-1356)',
    'Universal administrative site authority, user/commissioner/engineer role assignments, universal metadata vocabulary control, production orchestrator setup, and automated QC rule governance.',
    TRUE,
    '55555555-5555-4555-8555-555555555607'
),
(
    '55555555-5555-4555-8555-555555555613',
    '33333333-3333-4333-8333-333333333310',
    'diego_water_use_manager',
    'Water Use Program Data Manager (Diego Future Work Persona — PDF p. 21)',
    'All permissions of the water user plus Manage Systems review dashboard (notifications & all supplier boundary categories), except CANNOT edit boundary areas.',
    FALSE,
    '55555555-5555-4555-8555-555555555602'
)
ON CONFLICT (application_id, slug) DO NOTHING;

-- 7. Bind Allowed Identity Providers to DWRi Applications (with wiley_water_user as default JIT role)
INSERT INTO app_identity_providers (application_id, idp_id, allow_jit_signup, default_role_id) VALUES
('33333333-3333-4333-8333-333333333310', '11111111-1111-4111-8111-111111111101', TRUE, '55555555-5555-4555-8555-555555555602'),
('33333333-3333-4333-8333-333333333310', '11111111-1111-4111-8111-111111111102', TRUE, '55555555-5555-4555-8555-555555555602'),
('33333333-3333-4333-8333-333333333310', '11111111-1111-4111-8111-111111111103', TRUE, '55555555-5555-4555-8555-555555555604'),
('33333333-3333-4333-8333-333333333311', '11111111-1111-4111-8111-111111111101', FALSE, NULL),
('33333333-3333-4333-8333-333333333311', '11111111-1111-4111-8111-111111111102', FALSE, NULL),
('33333333-3333-4333-8333-333333333312', '11111111-1111-4111-8111-111111111101', FALSE, NULL),
('33333333-3333-4333-8333-333333333312', '11111111-1111-4111-8111-111111111102', FALSE, NULL),
('33333333-3333-4333-8333-333333333313', '11111111-1111-4111-8111-111111111101', FALSE, NULL),
('33333333-3333-4333-8333-333333333313', '11111111-1111-4111-8111-111111111103', FALSE, NULL)
ON CONFLICT DO NOTHING;

-- 8. Bind Permissions to Persona Roles
INSERT INTO role_permissions (role_id, permission_id, conditions) VALUES
-- Donna (Public Reader)
('55555555-5555-4555-8555-555555555601', '44444444-4444-4444-8444-444444444501', '{}'::jsonb),
('55555555-5555-4555-8555-555555555601', '44444444-4444-4444-8444-444444444502', '{}'::jsonb),
-- Wiley (Registered Water User)
('55555555-5555-4555-8555-555555555602', '44444444-4444-4444-8444-444444444503', '{}'::jsonb),
-- Parker (Public Water Supplier Representative — requires organization_id scope on assignment)
('55555555-5555-4555-8555-555555555603', '44444444-4444-4444-8444-444444444504', '{}'::jsonb),
('55555555-5555-4555-8555-555555555603', '44444444-4444-4444-8444-444444444505', '{}'::jsonb),
('55555555-5555-4555-8555-555555555603', '44444444-4444-4444-8444-444444444506', '{}'::jsonb),
-- Sarah (Scientist / Researcher / Consultant)
('55555555-5555-4555-8555-555555555604', '44444444-4444-4444-8444-444444444507', '{}'::jsonb),
('55555555-5555-4555-8555-555555555604', '44444444-4444-4444-8444-444444444508', '{}'::jsonb),
-- Cody (Commissioner & Deputy — scoped to assigned distribution_system or station)
('55555555-5555-4555-8555-555555555605', '44444444-4444-4444-8444-444444444510', '{}'::jsonb),
('55555555-5555-4555-8555-555555555605', '44444444-4444-4444-8444-444444444511', '{}'::jsonb),
('55555555-5555-4555-8555-555555555605', '44444444-4444-4444-8444-444444444512', '{}'::jsonb),
('55555555-5555-4555-8555-555555555605', '44444444-4444-4444-8444-444444444513', '{}'::jsonb),
('55555555-5555-4555-8555-555555555605', '44444444-4444-4444-8444-444444444514', '{}'::jsonb),
-- Fatima: Distribution Engineer ("Dory")
('55555555-5555-4555-8555-555555555606', '44444444-4444-4444-8444-444444444520', '{}'::jsonb),
('55555555-5555-4555-8555-555555555606', '44444444-4444-4444-8444-444444444521', '{}'::jsonb),
('55555555-5555-4555-8555-555555555606', '44444444-4444-4444-8444-444444444522', '{}'::jsonb),
('55555555-5555-4555-8555-555555555606', '44444444-4444-4444-8444-444444444523', '{}'::jsonb),
-- Fatima: Automation Engineer (adds raw withdrawal, telemetry IP/Pakbus security, asset scanning, staging orchestrator)
('55555555-5555-4555-8555-555555555607', '44444444-4444-4444-8444-444444444524', '{"require_mfa": true}'::jsonb),
('55555555-5555-4555-8555-555555555607', '44444444-4444-4444-8444-444444444525', '{}'::jsonb),
('55555555-5555-4555-8555-555555555607', '44444444-4444-4444-8444-444444444527', '{}'::jsonb),
('55555555-5555-4555-8555-555555555607', '44444444-4444-4444-8444-444444444528', '{"require_mfa": true}'::jsonb),
-- Fatima: Modeling Engineer (WCAT sync & diagnostics, NO hardware/Pakbus/raw-deletion)
('55555555-5555-4555-8555-555555555608', '44444444-4444-4444-8444-444444444510', '{}'::jsonb),
('55555555-5555-4555-8555-555555555608', '44444444-4444-4444-8444-444444444521', '{}'::jsonb),
('55555555-5555-4555-8555-555555555608', '44444444-4444-4444-8444-444444444526', '{}'::jsonb),
-- Fatima: Regional Office Engineer (adds WCAT model sync + water right enforcement within Regional Office ltree)
('55555555-5555-4555-8555-555555555612', '44444444-4444-4444-8444-444444444526', '{}'::jsonb),
('55555555-5555-4555-8555-555555555612', '44444444-4444-4444-8444-444444444529', '{}'::jsonb),
-- Diego: Statewide Data Steward (requires state_employee + MFA on governance actions)
('55555555-5555-4555-8555-555555555609', '44444444-4444-4444-8444-444444444530', '{"require_mfa": true, "allowed_user_types": ["state_employee"]}'::jsonb),
('55555555-5555-4555-8555-555555555609', '44444444-4444-4444-8444-444444444531', '{"require_mfa": true, "allowed_user_types": ["state_employee"]}'::jsonb),
('55555555-5555-4555-8555-555555555609', '44444444-4444-4444-8444-444444444532', '{"require_mfa": true, "allowed_user_types": ["state_employee"]}'::jsonb),
('55555555-5555-4555-8555-555555555609', '44444444-4444-4444-8444-444444444533', '{"require_mfa": true, "allowed_user_types": ["state_employee"]}'::jsonb),
-- Diego: Water Use Program Data Manager (PDF p. 21: views supplier systems & Manage Systems review, but NOT boundary editing)
('55555555-5555-4555-8555-555555555613', '44444444-4444-4444-8444-444444444504', '{}'::jsonb),
('55555555-5555-4555-8555-555555555613', '44444444-4444-4444-8444-444444444534', '{"require_mfa": true, "allowed_user_types": ["state_employee"]}'::jsonb)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 9. Replacing WCAT's 62 Hardcoded "Edit: [system]" Roles with 1 Scoped Role
-- ============================================================================
INSERT INTO permissions (id, application_id, resource_type, action, description) VALUES
('44444444-4444-4444-8444-444444444540', '33333333-3333-4333-8333-333333333311', 'distribution_system', 'read', 'View WCAT distribution system accounting'),
('44444444-4444-4444-8444-444444444541', '33333333-3333-4333-8333-333333333311', 'distribution_system', 'edit', 'Edit WCAT distribution system accounting (scoped by resource_id, e.g. weber-river)')
ON CONFLICT (application_id, resource_type, action) DO NOTHING;

INSERT INTO roles (id, application_id, slug, name, description, is_system_role) VALUES
(
    '55555555-5555-4555-8555-555555555610',
    '33333333-3333-4333-8333-333333333311',
    'wcat_system_editor',
    'WCAT Distribution System Editor',
    'Replaces all 62 "Edit: [system]" roles in wrsysDB; assign with resource_type=distribution_system and resource_id=<system_slug>.',
    TRUE
),
(
    '55555555-5555-4555-8555-555555555611',
    '33333333-3333-4333-8333-333333333311',
    'wcat_administrator_update_all',
    'WCAT Statewide Administrator',
    'Statewide WCAT editing across all 62 distribution systems (assigned with resource_id IS NULL).',
    TRUE
)
ON CONFLICT (application_id, slug) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id, conditions) VALUES
('55555555-5555-4555-8555-555555555610', '44444444-4444-4444-8444-444444444540', '{}'::jsonb),
('55555555-5555-4555-8555-555555555610', '44444444-4444-4444-8444-444444444541', '{}'::jsonb),
('55555555-5555-4555-8555-555555555611', '44444444-4444-4444-8444-444444444540', '{}'::jsonb),
('55555555-5555-4555-8555-555555555611', '44444444-4444-4444-8444-444444444541', '{"require_mfa": true}'::jsonb)
ON CONFLICT DO NOTHING;
