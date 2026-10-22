# Utah Common Authentication & Authorization (Zero Trust IAM / PDP)

A centralized **Zero Trust Authentication & Fine-Grained Authorization Service** built in **Go** for **GCP Cloud Run** and **Cloud SQL for PostgreSQL**.

Designed for State of Utah applications (such as Utah Division of Water Resources GIS & modeling portals) to support:
- **UtahID (OIDC)** for State employees and citizens
- **External Identity Providers** (GCP Identity Platform, Microsoft Entra ID, Google Workspace) for external water conservancy districts, municipalities, federal partners, and engineering consultants
- **Dynamic App, Role & Permission Registration** via REST API (`/v1/admin/*`)
- **Hybrid RBAC + Resource-Instance Scoping + ABAC** (Organization `ltree` hierarchy inheritance, specific `resource_id` grants, Explicit `deny` overrides, IP CIDR restrictions, MFA enforcement, and time-bound contractor access)

---

## Documentation Guides

- 📘 **[Developer Guide (`docs/DEVELOPER_GUIDE.md`)](./docs/DEVELOPER_GUIDE.md)** — Architecture deep-dive, local development setup, PostgreSQL schema & scoping reference, complete REST API reference, and downstream SDK integration examples.
- 🏛️ **[DWRi Personas, Figma Mockups & Legacy Migration Guide (`docs/DWRI_PERSONAS_AND_LEGACY_MIGRATION.md`)](./docs/DWRI_PERSONAS_AND_LEGACY_MIGRATION.md)** — Complete mapping of the 6 Personas (Donna, Wiley/Parker, Sarah, Cody/Deputies, Fatima's 4 Engineer profiles, and Diego) from the 72-page 2026 UCD PDF, Figma prototypes, and the 4 legacy permission stores (`wrsysDB`, `DVRTEDIT`, `Water Use Program`, `HydroServer`).
- 🚀 **[GCP Deployment Guide (`docs/DEPLOYMENT_GUIDE.md`)](./docs/DEPLOYMENT_GUIDE.md)** — Step-by-step instructions for provisioning Cloud SQL for PostgreSQL 16, GCP Secret Manager keys, least-privilege IAM service accounts, Cloud Run deployment, and production UtahID configuration.

---

## Repository Structure

```text
├── cmd/authz-server/main.go        # Cloud Run HTTP server entrypoint
├── docs/
│   ├── DEVELOPER_GUIDE.md          # Complete developer & API integration reference
│   └── DEPLOYMENT_GUIDE.md         # Step-by-step GCP Cloud Run & Cloud SQL deployment guide
├── internal/
│   ├── api/                        # REST handlers & Zero Trust admin middleware
│   ├── authn/                      # Multi-Issuer OIDC verifier & RFC 8693 Token Exchange (ES256 JWKS)
│   ├── authz/                      # Zero Trust Policy Decision Point (PDP) & ABAC evaluator
│   ├── config/                     # Environment & Cloud SQL socket configuration
│   ├── db/                         # Cloud SQL PostgreSQL (pgx/v5) & in-memory test store
│   └── domain/                     # Canonical domain models
├── migrations/
│   ├── 000001_init_schema.up.sql   # Complete PostgreSQL DDL (ltree, pgcrypto, indexes)
│   └── 000002_seed_utah_defaults.up.sql
├── pkg/authzclient/                # Reusable Go SDK & HTTP middleware for downstream Utah apps
├── docker-compose.yml              # One-command local PostgreSQL 16 + AuthZ Server stack
└── Dockerfile                      # Multi-stage distroless container for GCP Cloud Run
```

---

## Quick Start

### 1. Run End-to-End Tests (No External DB Required)
```bash
go test -v ./...
```

### 2. Start Local Stack with Docker Compose
Starts PostgreSQL 16 (automatically applying migrations and seed data) and the Go `authz-server` on `http://localhost:8080`:
```bash
docker compose up --build
```

### 3. Core API Workflows

#### Register a New Application, Permission & Role
```bash
export ADMIN_BOOTSTRAP_API_KEY="dev-utah-bootstrap-secret"

# 1. Register a new application
curl -X POST http://localhost:8080/v1/admin/apps \
  -H "X-Admin-Bootstrap-Key: $ADMIN_BOOTSTRAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "slug": "water-rights-portal",
    "name": "Utah Water Rights Portal",
    "token_ttl_seconds": 900,
    "require_mfa": false,
    "is_active": true
  }'

# 2. Define a fine-grained permission
curl -X POST http://localhost:8080/v1/admin/apps/water-rights-portal/permissions \
  -H "X-Admin-Bootstrap-Key: $ADMIN_BOOTSTRAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_type": "basin_model",
    "action": "write",
    "description": "Modify basin hydrologic models"
  }'

# 3. Create a role and attach permissions
curl -X POST http://localhost:8080/v1/admin/apps/water-rights-portal/roles \
  -H "X-Admin-Bootstrap-Key: $ADMIN_BOOTSTRAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "slug": "basin_editor",
    "name": "Basin Model Editor",
    "permission_ids": ["<PERMISSION_UUID>"]
  }'
```

#### Exchange UtahID or External OIDC Token for an App-Scoped JWT
```bash
curl -X POST http://localhost:8080/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "subject_token": "<UTAHID_OR_EXTERNAL_OIDC_ID_TOKEN>",
    "target_app": "water-rights-portal"
  }'
```

#### Real-Time Zero Trust Authorization Check (`/v1/authorize`)
```bash
curl -X POST http://localhost:8080/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "principal_id": "<USER_UUID>",
    "app_slug": "water-rights-portal",
    "resource_type": "basin_model",
    "resource_id": "bear-river-basin",
    "action": "write",
    "context": {
      "client_ip": "204.113.10.25",
      "mfa_verified": true
    }
  }'
```
