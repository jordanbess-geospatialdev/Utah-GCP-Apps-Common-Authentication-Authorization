# Developer Guide — Utah Common Authentication & Authorization

This guide covers the architecture, local development workflow, database schema, API specifications, and SDK integration patterns for the **Utah Common Authentication & Authorization (Zero Trust IAM / PDP)** service.

---

## Table of Contents
1. [Core Architecture & Zero Trust Model](#1-core-architecture--zero-trust-model)
2. [Local Development Setup](#2-local-development-setup)
3. [Database Schema & Scoping Concepts](#3-database-schema--scoping-concepts)
4. [Complete REST API Reference](#4-complete-rest-api-reference)
5. [Integrating Downstream Applications](#5-integrating-downstream-applications)
6. [Adding New Features & Running Tests](#6-adding-new-features--running-tests)

---

## 1. Core Architecture & Zero Trust Model

State of Utah applications must support two distinct populations:
1. **Internal State Users**: Authenticated via **UtahID (OIDC)** (`https://id.utah.gov/oauth2/default`).
2. **External Partners & Citizens**: Water conservancy districts, municipalities, federal partners (USGS, BOR), and engineering consultants authenticated via **GCP Identity Platform**, **Microsoft Entra ID**, **Google Workspace**, or generic OIDC providers.

### Two-Stage Zero Trust Flow

```mermaid
sequenceDiagram
    autonumber
    participant User as User / Browser SPA
    participant IdP as UtahID or External OIDC
    participant AuthZ as Common AuthN/AuthZ Service
    participant App as Downstream Utah App (e.g. Water Map API)
    participant DB as Cloud SQL PostgreSQL

    User->>IdP: Authenticate via OIDC Authorization Code + PKCE
    IdP-->>User: Upstream OIDC ID Token
    User->>AuthZ: POST /v1/auth/token (subject_token, target_app="water-resources-map")
    AuthZ->>IdP: Verify signature via cached OIDC JWKS
    AuthZ->>DB: Resolve/JIT-provision canonical User, sync groups, verify App-IdP trust
    AuthZ-->>User: Short-lived (15m) ES256 JWT (aud="water-resources-map", sub=user_uuid, roles=[...])
    User->>App: API Request + Authorization: Bearer <app_jwt>
    App->>AuthZ: POST /v1/authorize (principal_id, app_slug, resource_type, resource_id, action, context)
    AuthZ->>DB: Single-pass recursive SQL check (RBAC + Org ltree + Resource ID)
    AuthZ->>AuthZ: Evaluate ABAC Conditions (MFA, CIDR, Time Window, Attributes)
    AuthZ-->>App: {"allowed": true, "decision": "allow", "matched_role": "dwre_hydrologist"}
    App-->>User: 200 OK (Protected GIS / Water Resource Data)
```

### Deterministic Evaluation Precedence (`internal/authz/pdp.go`)
Every call to `/v1/authorize` evaluates rules in strict order:
1. **Principal Verification**: The canonical user in `users` must exist and have `status = 'active'`.
2. **Application Verification**: The target app in `applications` must exist, have `is_active = true`, and if `require_mfa = true`, the request context must have `mfa_verified = true`.
3. **Candidate Grant Resolution**: Queries `role_assignments` for active grants (`starts_at <= NOW()` and `expires_at IS NULL OR expires_at > NOW()`) matching the user directly (`principal_type = 'user'`) or via `group_memberships` (`principal_type = 'group'`).
4. **Explicit `DENY` Override**: If **any** matching grant has `effect = 'deny'` (and its ABAC conditions match), the request is **immediately denied** (`reason: "explicit_deny_rule"`), regardless of any other `allow` grants.
5. **Explicit `ALLOW` + ABAC Check**: Evaluates both `role_assignments.conditions` and `role_permissions.conditions` for every candidate `allow` grant. If at least one grant passes all ABAC checks, the request is **allowed**.
6. **Default Deny**: If no rule explicitly permits the action, the request is **denied**.

---

## 2. Local Development Setup

### Prerequisites
- **Go 1.23+** (tested with Go 1.27)
- **Docker & Docker Compose** (for local PostgreSQL 16)

### Option A: One-Command Docker Compose
Starts PostgreSQL 16 (automatically applying `migrations/000001_init_schema.up.sql` and `migrations/000002_seed_utah_defaults.up.sql`) and the `authz-server` on `http://localhost:8080`:

```bash
docker compose up --build
```

### Option B: Run Go Natively Against Local Postgres
1. Start only the PostgreSQL container:
   ```bash
   docker compose up -d postgres
   ```
2. Export environment variables and run the server:
   ```bash
   export PORT="8080"
   export ENVIRONMENT="development"
   export DATABASE_URL="postgres://postgres:postgres@localhost:5432/utah_authz?sslmode=disable"
   export AUTHZ_ISSUER_URL="http://localhost:8080"
   export ADMIN_BOOTSTRAP_API_KEY="dev-utah-bootstrap-secret"

   go run ./cmd/authz-server
   ```

### Environment Variables Reference (`internal/config/config.go`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `8080` | HTTP listen port (injected automatically by GCP Cloud Run) |
| `ENVIRONMENT` | `development` | Runtime environment (`development`, `staging`, `production`) |
| `DATABASE_URL` | *(constructed)* | Full PostgreSQL connection string; overrides `DB_*` variables |
| `INSTANCE_UNIX_SOCKET` | *(empty)* | Cloud SQL Unix socket path on Cloud Run (e.g. `/cloudsql/proj:region:inst`) |
| `DB_HOST` / `DB_PORT` | `localhost` / `5432` | TCP host/port when `DATABASE_URL` and `INSTANCE_UNIX_SOCKET` are unset |
| `DB_USER` / `DB_PASS` / `DB_NAME` | `postgres` / `postgres` / `utah_authz` | Database credentials |
| `AUTHZ_ISSUER_URL` | `https://authz.utah.gov` | `iss` claim stamped into exchanged App JWTs |
| `AUTHZ_SIGNING_KEY_ID` | `utah-zero-trust-key-2026-01` | `kid` header in exchanged JWTs and `/.well-known/jwks.json` |
| `AUTHZ_SIGNING_PRIVATE_KEY_PEM` | *(ephemeral in dev)* | ECDSA P-256 private key PEM for signing exchanged App JWTs |
| `ADMIN_BOOTSTRAP_API_KEY` | *(empty)* | Optional bootstrap key accepted via `X-Admin-Bootstrap-Key` header |

---

## 3. Database Schema & Scoping Concepts

### Scoping Levels on `role_assignments`
When an administrator assigns a role to a User or Group in `role_assignments`, they choose one of three scopes:

| Scope Type | `organization_id` | `resource_type` & `resource_id` | Behavior |
| :--- | :--- | :--- | :--- |
| **1. App-Global** | `NULL` | `NULL` | Grants the role across the entire application regardless of organization or resource ID. |
| **2. Organization / Tenant** | `<org_uuid>` | `NULL` | Grants the role for that organization. If `include_child_orgs = true`, automatically applies to all child divisions via PostgreSQL `ltree` (e.g. granting at `state_of_utah.dnr` covers `state_of_utah.dnr.dwre`). |
| **3. Resource Instance** | `NULL` (or `<org_uuid>`) | `"basin_layer"`, `"bear-river"` | Grants the role **only** on that specific resource instance (`resource_type = 'basin_layer' AND resource_id = 'bear-river'`). |

### Supported ABAC Conditions (`ABACConditions` JSONB)
Both `role_assignments.conditions` and `role_permissions.conditions` accept a JSON object with any combination of the following fields:

```json
{
  "require_mfa": true,
  "ip_cidrs": ["204.113.0.0/16", "10.0.0.0/8"],
  "allowed_user_types": ["state_employee"],
  "required_attributes": {
    "division": "DWRe",
    "security_training": "current"
  },
  "allowed_hours_utc": {
    "start_hour": 12,
    "end_hour": 23
  }
}
```

---

## 4. Complete REST API Reference

### Public & Runtime Endpoints

#### `GET /healthz`
Returns service health for Cloud Run startup/liveness probes.

#### `GET /.well-known/jwks.json`
Returns the public ECDSA P-256 JSON Web Key Set (`JWKS`) used to verify tokens issued by `POST /v1/auth/token`.

#### `POST /v1/auth/token` — Token Exchange
Exchanges an upstream UtahID or External OIDC ID token for a short-lived, audience-scoped JWT. The `subject_token` may also be a **Google Identity-Aware Proxy signed-header assertion** (`x-goog-iap-jwt-assertion`) when the active `google-iap` IdP's `client_id` lists the service audience — see the [IAP Integration Guide](./IAP_INTEGRATION.md).
- **Request**:
  ```json
  {
    "subject_token": "<UPSTREAM_OIDC_ID_TOKEN>",
    "target_app": "water-resources-map",
    "organization_id": "22222222-2222-4222-8222-222222222203"
  }
  ```
- **Response (`200 OK`)**:
  ```json
  {
    "access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6...",
    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "token_type": "Bearer",
    "expires_in": 900,
    "app_slug": "water-resources-map",
    "user": {
      "id": "0192b4a0-...",
      "email": "engineer@utah.gov",
      "user_type": "state_employee",
      "status": "active"
    },
    "roles": ["dwre_hydrologist"]
  }
  ```

#### `POST /v1/authorize` — Real-Time Zero Trust Check
Evaluates whether a principal is permitted to perform an action on a resource.
- **Request**:
  ```json
  {
    "principal_id": "0192b4a0-...",
    "app_slug": "water-resources-map",
    "resource_type": "basin_layer",
    "resource_id": "jordan-river-basin",
    "action": "write",
    "organization_id": "22222222-2222-4222-8222-222222222203",
    "context": {
      "client_ip": "204.113.42.10",
      "mfa_verified": true,
      "attributes": {
        "division": "DWRe"
      }
    }
  }
  ```
- **Response (`200 OK`)**:
  ```json
  {
    "allowed": true,
    "decision": "allow",
    "reason": "grant_matched",
    "matched_role": "dwre_hydrologist",
    "assignment_id": "8f14e45f-...",
    "evaluated_at": "2026-10-22T21:00:00Z"
  }
  ```

#### `POST /v1/authorize/batch` — Batch Resource/UI Evaluation
Evaluates up to 100 checks in a single call (ideal for filtering visible GIS layers or UI actions on page load).
- **Request**:
  ```json
  {
    "principal_id": "0192b4a0-...",
    "app_slug": "water-resources-map",
    "context": { "mfa_verified": true },
    "checks": [
      { "check_id": "edit_jordan", "resource_type": "basin_layer", "resource_id": "jordan-river", "action": "write" },
      { "check_id": "edit_bear", "resource_type": "basin_layer", "resource_id": "bear-river", "action": "write" }
    ]
  }
  ```

---

### Admin Control Plane Endpoints (`/v1/admin/*`)
All admin endpoints require either:
- `Authorization: Bearer <token_exchanged_for_utah-iam-admin>` with the required admin permission (`application:manage`, `assignment:manage`, or `*:*`), **OR**
- `X-Admin-Bootstrap-Key: <ADMIN_BOOTSTRAP_API_KEY>` (when bootstrap key is enabled).

| Method & Path | Description |
| :--- | :--- |
| `GET /v1/admin/idps` | List all registered OIDC Identity Providers |
| `POST /v1/admin/idps` | Register a new OIDC Identity Provider (UtahID, GCP Identity Platform, Entra ID, Google) |
| `GET /v1/admin/organizations` | List all Organizations ordered by `ltree` hierarchy path |
| `POST /v1/admin/organizations` | Create a new Organization (e.g., `state_of_utah.dnr.dwre` or `external_orgs.jvwcd`) |
| `POST /v1/admin/groups` | Create a Group (with optional `external_idp_id` + `external_group_id` for OIDC claim sync) |
| `POST /v1/admin/groups/{groupID}/members` | Add a User to a Group with optional `expires_at` |
| `GET /v1/admin/users` | List canonical federated users |
| `GET /v1/admin/apps` | List all registered Applications |
| `POST /v1/admin/apps` | Register a new Application (`slug`, `name`, `token_ttl_seconds`, `require_mfa`) |
| `POST /v1/admin/apps/{appSlug}/idps` | Allow an Identity Provider to authenticate into `{appSlug}` |
| `GET /v1/admin/apps/{appSlug}/permissions` | List all `resource_type:action` permissions defined for `{appSlug}` |
| `POST /v1/admin/apps/{appSlug}/permissions` | Register a new `resource_type:action` permission for `{appSlug}` |
| `GET /v1/admin/apps/{appSlug}/roles` | List all roles defined for `{appSlug}` |
| `POST /v1/admin/apps/{appSlug}/roles` | Create a new Role (supports `inherits_from` and inline `permission_ids`) |
| `POST /v1/admin/apps/{appSlug}/roles/{roleSlug}/permissions` | Attach a permission (with optional ABAC `conditions`) to an existing Role |
| `GET /v1/admin/apps/{appSlug}/assignments` | List all scoped role assignments for `{appSlug}` |
| `POST /v1/admin/apps/{appSlug}/assignments` | Grant (`allow`) or block (`deny`) a Role for a User/Group at Global, Org, or Resource scope |
| `DELETE /v1/admin/apps/{appSlug}/assignments/{assignmentID}` | Revoke a role assignment immediately |

---

## 5. Integrating Downstream Applications

### Go Applications (`pkg/authzclient`)
Downstream Go services can import `github.com/utah-dnr/utah-gcp-common-authz/pkg/authzclient` to protect HTTP handlers with one line of middleware:

```go
package main

import (
	"net/http"

	"github.com/utah-dnr/utah-gcp-common-authz/pkg/authzclient"
)

func main() {
	authz := authzclient.NewClient("https://authz.water.utah.gov", "water-resources-map")

	mux := http.NewServeMux()

	// Protect route with Zero Trust resource-level check:
	// Extracts the target basin ID from the URL path and verifies 'basin_layer:write'
	updateBasinHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := authzclient.PrincipalFromContext(r.Context())
		w.Write([]byte("Updated by " + principal.Email))
	})

	mux.Handle("PUT /api/basins/{basinID}",
		authz.RequirePermission("basin_layer", "write", func(r *http.Request) string {
			return r.PathValue("basinID")
		})(updateBasinHandler),
	)

	http.ListenAndServe(":8081", mux)
}
```

### Applications Fronted by Google Identity-Aware Proxy (IAP)
If the downstream service sits behind **Google Cloud Identity-Aware Proxy**, browsers are authenticated at the edge and arrive with the signed `x-goog-iap-jwt-assertion` header instead of a Bearer token. Chain `IAPTokenExchange` **outside** `RequirePermission` — it locally verifies the assertion's signature against Google IAP's published public keys, exchanges it for this app's Zero Trust JWT (cached per verified user until shortly before expiry), and injects it as the Bearer credential:

```go
authz := authzclient.NewClient("https://authz.water.utah.gov", "water-resources-map",
	authzclient.WithExpectedIssuer("https://authz.water.utah.gov"), // pin 'iss' in production
)

protected := authz.IAPTokenExchange(nil)(            // 1. verify + exchange IAP assertion (cached)
	authz.RequirePermission("basin_layer", "read", nil)( // 2. fine-grained Zero Trust PDP check
		mux,                                              // 3. your handlers
	))
```

Requests without an IAP header pass through untouched (direct Bearer/service-to-service callers keep working); when the header is present it is **signature-verified locally first** (a forged assertion can never be used to look up another user's cached token) and the IAP-verified identity always wins over a client-supplied `Authorization` header. Requires the seeded `google-iap` IdP to be activated with your service's audience — see the **[IAP Integration Guide](./IAP_INTEGRATION.md)**.

### Token verification & PDP security model
- `RequirePermission` cryptographically verifies every Bearer token (ES256 signature via the authz service's `/.well-known/jwks.json`, `aud == <your app slug>`, and expiry; `iss` too when `WithExpectedIssuer` is set) before any policy call. Unsigned or tampered tokens are rejected with `401`.
- `POST /v1/authorize` and `/v1/authorize/batch` require the caller's Bearer app token. A token scoped to your app may only evaluate **its own** `sub` as `principal_id`; tokens scoped to `utah-iam-admin` may evaluate any principal (admin console). Identity context (`mfa`, `user_type`) is taken from the verified token, not the request body.

### Python / Node.js / GIS Backend Applications
Non-Go services integrate using two standard HTTP calls:
1. Verify the incoming `Authorization: Bearer <app_jwt>` signature against `GET https://authz.water.utah.gov/.well-known/jwks.json` and check `aud == "<your_app_slug>"`.
2. Call `POST https://authz.water.utah.gov/v1/authorize` with the **same Bearer token** in the `Authorization` header, and the token's `sub` (`principal_id`), `resource_type`, `resource_id`, and `action` in the body. The service enforces `principal_id == sub` for app-scoped tokens.

---

## 6. Adding New Features & Running Tests

Run the full test suite (includes end-to-end API tests in `internal/api/server_test.go` and ABAC condition unit tests in `internal/authz/abac_test.go`):

```bash
go test -v -race ./...
```
