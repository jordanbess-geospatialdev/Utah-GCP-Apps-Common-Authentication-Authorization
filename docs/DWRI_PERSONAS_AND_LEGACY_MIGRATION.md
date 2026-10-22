# DWRi Personas, Figma Mockups & Legacy Permission Stores Migration Guide

This guide documents how the **Utah Division of Water Rights (DWRi)** requirements from:
1. ***Updated 2026 User-Centric Design Requirements for the Water Measurement Data Dashboard*** (72-page Sep 2026 Draft)
2. ***Six Figma Persona Prototypes*** (`figma-links.txt` — `Data-System-Template`)
3. ***Current Roles and Permissions Architecture at DWRi*** (Adel Abdallah, Tech Services, Oct 2026)
4. ***Division of Water Rights Plan to Reduce Technical Debt*** (2026)

are implemented and enforced in this **Common Zero Trust Authentication & Authorization** service.

---

## 1. Eliminating Legacy DWRi Security & Architecture Debt

| Legacy System Vulnerability / Limitation | Source Document | How the New Zero Trust Service Solves It |
| :--- | :--- | :--- |
| **1. Public Network IP-Address Session Hijacking** | *Technical Debt Plan 2026*, pp. 8–9 | Legacy `login.waterrights.utah.gov` stored a user's external IP in a `logged-in-user` table—meaning anyone on the same conference Wi-Fi / NAT IP inherited that staff member's identity and permissions. Replaced by **RFC 8693 Token Exchange (`POST /v1/auth/token`)** issuing short-lived (15 min) ES256-signed JWTs bound to the individual user (`sub`) and target application (`aud`). Client IP is only used as an *additional* ABAC restriction (`ip_cidrs`), never as an identity token. |
| **2. Four Disconnected Permission Silos (No API)** | *Current Roles & Permissions*, p. 1 | Legacy DWRi split access across `wrsysDB` (40 apps), `DVRTEDIT`, `Water Use Program`, and `HydroServer`, each queried via direct SQL with separate admin screens. Unified into a single Cloud SQL PostgreSQL store behind `POST /v1/authorize` and `POST /v1/authorize/batch`. |
| **3. 62 Hardcoded WCAT System Role Names** | *Current Roles & Permissions*, pp. 3–6 | Legacy WCAT created 62 separate role strings (`"Edit: WEBER RIVER"`, `"LOWER BEAR - IDAHO"`) because `sitePermissions` had no scope column. Replaced with **1 role** (`wcat_system_editor` / `cody_commissioner`) scoped via `resource_type = "distribution_system"` and `resource_id = "weber-river"`. |
| **4. No Groups ("Repeated Role Sets") & Role Concentration** | *Current Roles & Permissions*, p. 4 | Legacy `wrsysDB` had no groups: 6 Regional Office staff required **101 individual grant rows**, 18 Well Drilling staff, 11 MailLog staff, and 5 wrEntry editors were granted one row at a time, while James Reese (62 roles) and David Jones (50 roles) held 30% of all grants. Replaced with **`groups`** (`dwri-regional-office-staff`, `dwri-well-drilling-staff`, `dwri-maillog-staff`, `dwri-water-right-entry-editors`) and the **7 DWRi Regional Office `ltree` organizations**. |
| **5. No Expiry, Deputy Delegation, or Audit History** | *Current Roles & Permissions*, pp. 4, 6 | Legacy tables held shared accounts (`"Microfilm Workstation"`), external USGS staff, and former employees with no `granted_by`, `justification`, or `expires_at`. Every `role_assignments` row now tracks `granted_by`, `justification`, `starts_at`, and `expires_at` (enforcing automatic expiration for seasonal Deputy Commissioners and external contractors) and logs to `audit_logs`. |

---

## 2. The 6 Personas & Sub-Personas (2026 UCD PDF + `figma-links.txt`)

Migration [`000003_seed_dwri_personas_and_apps.up.sql`](../migrations/000003_seed_dwri_personas_and_apps.up.sql) seeds the `dwri-water-measurement-dashboard` application, its 23 atomic `resource_type:action` permissions, and 11 hierarchical Persona & Sub-Persona roles matching the 72-page PDF and Figma flows.

### Summary Matrix of Personas, Figma Nodes, and Zero Trust Roles

| Persona / Sub-Persona | Named Stakeholders in 2026 PDF | Figma Prototype (`Data-System-Template`) | Role Slug in AuthZ Service | Scoping & ABAC Guardrails |
| :--- | :--- | :--- | :--- | :--- |
| **1. Donna** (Director, Auditor, Legislator, Citizen) | Teresa (Director/Compact planning), Brian (GSL Water Rights Fund), Legislative Auditors | Page `81:364`, Node `81-365` | `donna_public_reader` | Public read of published stations, FAIR data dictionary, legislative KPIs, WestDAAT summaries (`published_station:read`, `public_export:create`). Auto-upgrades to `wiley_water_user` on JIT account creation (PDF p. 58). |
| **2a. Wiley** (Water Rights Owner, Farmer, Rancher, Canal Co.) | Farmers, ranchers, canal & irrigation companies | Page `0:1`, Node `1193-1908`* | `wiley_water_user` | Default JIT role on login. Adds `user_preference:manage_own` ("My Sites" favorites, alerts, tea-cup diagrams, PDF pp. 52–54). Favoriting a site never grants edit authority. |
| **2b. Parker** (Public Water Supplier — Water Use Program) | Cities, JVWCD, CUWCD, PRWUA, Salt Lake County | Page `0:1`, Node `1193-1908`* ("My System" portal) | `parker_water_supplier` | **Organization-Scoped (`organization_id = <supplier_org_uuid>`)**. Grants `supplier_system:read`, `supplier_boundary:propose`, and `supplier_report:submit` only for that supplier's assigned area (PDF pp. 54–56). |
| **3. Sarah** (Scientist, Researcher, Consultant) | Bart (CRAU), Chad (former Richfield DWRi staff consulting), USGS, BOR, USU, OpenET | Page `1601:12578`, Node `1601-13148` | `sarah_researcher` | Default JIT role for `research-orcid-oidc`. Grants `research_dataset:read` (provisional vs. best-available queries) and `api_token:manage_own` (self-service token rotation/revocation, PDF pp. 66–70). |
| **4. Cody** (Water Commissioner & Deputies — ~55 statewide) | Kent Wilkerson (Weber/Ogden), Porter Monroe (Lower Sevier), David Jessop (Virgin), Michael Lasswell (Logan), Brayden Rindlisbach (Upper Jordan), Scott Bergendorf (Provo), Clinton Hansen (Little Bear), Jay Leavitt (Santa Clara) | Page `396:2979`, Node `1193-1908`* | `cody_commissioner` | **Resource-Scoped (`resource_type = "distribution_system"`, `resource_id = "<system_slug>"`)**. Deputies receive time-bounded (`starts_at` / `expires_at`) grants. Offline mobile drafts (`FR-027`) re-verify authorization on sync. |
| **5a. Fatima — Distribution Engineer ("Dory")** | Jacob Olsen, Ian Stockdill, Caleb McCurry, David Horsley, Tim Heyrend, Michael Nay | Page `545:7949`, Node `545-8730` | `fatima_distribution_engineer` | **System or Region Scoped**. Creates sites/datastreams (`station:create`), views battery voltage (`diagnostics:read`), logs rating curve shifts (`site_visit:manage`), uploads internal photos (`attachment_internal:manage`, PDF p. 38 Table 2). |
| **5b. Fatima — Automation Engineer** | Cole Panter, Alexander Heilig, Susan Odekirk | Page `545:7949`, Node `545-8730` + Smartphone App | `fatima_automation_engineer` | Adds `raw_observation:withdraw` (delete/exclude erroneous raw readings, **requires MFA**), `telemetry_address:manage` (Cell IP/Port, Radio, Pakbus security, **requires MFA**), `asset_inventory:manage`, and `ingestion_connection:request` (PDF pp. 38, 42, 47, 49). |
| **5c. Fatima — Regional Engineer** | Skyler Buck (Northern), Cash Stallings (Southeastern) across 7 Regional Offices | Page `545:7949`, Node `545-8730` | `fatima_regional_engineer` | **Organization-Scoped (`ltree` `state_of_utah.dnr.dwri.region_*`)**. Supervises regional distribution systems, operates river models (`wcat_model:sync`), and assists with enforcement (`enforcement:assist`, PDF p. 38 Table 2). |
| **5d. Fatima — Modeling Engineer** | Teresa (Sevier WCAT), Ed Vidmar (Spanish Fork WCAT), Cole Panter (Jordan/Little Cottonwood WCAT) | Page `545:7949`, Node `545-8730` | `fatima_modeling_engineer` | Inherits from `sarah_researcher` (NOT `cody_commissioner`). Grants `wcat_model:sync`, `diagnostics:read`, and `distribution_system:read_restricted`—**without** station hardware, Pakbus security, or raw-deletion privileges. |
| **6a. Diego — Data Steward / QA-QC Manager** | Adel Abdallah, Alexander Heilig, Jim, Jared, Leah (Data Services Section) | Page `173:600`, Node `173-1356` | `diego_data_steward` | **Statewide Scope + ABAC (`require_mfa: true`, `allowed_user_types: ["state_employee"]`)**. Sole authority for `vocabulary:manage`, `ingestion_connection:manage`, `qc_rule:manage`, and `user_assignment:manage` (PDF pp. 17–22). |
| **6b. Diego — Water Use Program Data Manager** | Water Use Program review staff (PDF p. 21) | Page `173:600`, Node `173-1356` | `diego_water_use_manager` | Grants `wiley_water_user` + `supplier_system:read` + `supplier_system:manage_review` ("Manage Systems" dashboard), while omitting/denying `supplier_boundary:propose` (*"All the same permissions as the water user, except cannot edit boundary areas"*, PDF p. 21). |

> **\*Note on Figma Node `1193-1908` (`figma-links.txt`)**: In `figma-links.txt`, both the **Cody (Commissioner)** link (`page-id=396:2979`) and the **Wiley (Water User)** link (`page-id=0:1`) specify `starting-point-node-id=1193:1908` on different pages. In our Zero Trust authorization layer, their entitlements are strictly separated: `wiley_water_user` can only manage personal favorites/alerts (`user_preference:manage_own`), whereas `cody_commissioner` requires an explicit, server-validated `role_assignment` scoped to a specific `distribution_system` (`resource_id`).

---

## 3. Concrete Setup Recipes for Key DWRi Workflows

### Recipe A: Assigning Commissioners & Seasonal Deputies (Cody Persona, PDF pp. 23–35)
Kent S. Wilkerson is the appointed Water Commissioner for the **Weber and Ogden** distribution systems, and delegates a seasonal Deputy Commissioner for the 2026 irrigation season:

```bash
# 1. Assign Kent Wilkerson as Commissioner for Weber River
curl -X POST http://localhost:8080/v1/admin/apps/dwri-water-measurement-dashboard/assignments \
  -H "Authorization: Bearer $DIEGO_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role_slug": "cody_commissioner",
    "principal_type": "user",
    "user_id": "<KENT_USER_UUID>",
    "effect": "allow",
    "resource_type": "distribution_system",
    "resource_id": "weber-river",
    "justification": "Appointed Water Commissioner for Weber River Distribution System"
  }'

# 2. Delegate a Deputy Commissioner with automatic end-of-season expiration (FR-011)
curl -X POST http://localhost:8080/v1/admin/apps/dwri-water-measurement-dashboard/assignments \
  -H "Authorization: Bearer $DIEGO_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role_slug": "cody_commissioner",
    "principal_type": "user",
    "user_id": "<DEPUTY_USER_UUID>",
    "effect": "allow",
    "resource_type": "distribution_system",
    "resource_id": "weber-river",
    "starts_at": "2026-04-15T00:00:00Z",
    "expires_at": "2026-10-31T23:59:59Z",
    "justification": "2026 irrigation season deputy delegation for Weber River"
  }'
```

### Recipe B: Separating the 4 Engineer Profiles (Fatima Persona, PDF p. 38 Table 2 & pp. 45–49)
The 2026 PDF highlights sensitive field capabilities that must be isolated within the engineer family:
1. **Internal Photos, Gate Codes & Wiring Details (`attachment_internal:manage`, PDF p. 45)**: Granted to `fatima_distribution_engineer`, `fatima_regional_engineer`, and `fatima_automation_engineer`, but **never** exposed to `donna_public_reader`, `wiley_water_user`, `sarah_researcher`, or `fatima_modeling_engineer`.
2. **Cell IP/Port, Radio Addresses & Pakbus Security (`telemetry_address:manage`, PDF pp. 47, 49)** and **Deleting/Withdrawing Erroneous Raw Readings (`raw_observation:withdraw`, PDF p. 42)**: Restricted exclusively to `fatima_automation_engineer` (and `diego_data_steward`) with an ABAC condition requiring **MFA (`{"require_mfa": true}`)**.
3. **Regional Office Supervision (`fatima_regional_engineer`, PDF p. 2 & p. 38)**: Assigned at any of the 7 DWRi Regional Office `ltree` nodes (`dwri-region-northern-logan`, `dwri-region-weber-ogden`, `dwri-region-utah-lake-jordan`, `dwri-region-vernal`, `dwri-region-southeastern-price`, `dwri-region-sevier-richfield`, `dwri-region-southern-cedar`).

### Recipe C: Enforcing the Water Use Program Data Manager Boundary (PDF p. 21)
PDF page 21 specifies that the **Water Use Program Data Manager** has *"all the same permissions as the water user, except cannot edit boundary areas"* plus access to the *"Manage Systems"* review dashboard.
Even if a staff member holds both `parker_water_supplier` and `diego_water_use_manager`, an administrator can attach an **Explicit `DENY` rule** on `supplier_boundary:propose` (or use `diego_water_use_manager` which omits `supplier_boundary:propose`), guaranteeing deterministic enforcement at `/v1/authorize`.
