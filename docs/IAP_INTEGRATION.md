# Google Cloud Identity-Aware Proxy (IAP) Integration Guide

This guide explains how to put **Google Cloud Identity-Aware Proxy (IAP)** in front of your
downstream Utah applications while keeping this service as the fine-grained Zero Trust
Policy Decision Point (PDP).

---

## 1. How IAP and This Service Fit Together

The two layers solve different problems and complement each other:

| Layer | Google IAP | Utah Common AuthN/AuthZ (this service) |
|---|---|---|
| Role | Edge authentication & coarse access control | Application token exchange & fine-grained authorization |
| Answers | *"Who is reaching this application?"* | *"May this user perform this action on this resource?"* |
| Identity | Google accounts, Google Workspace, or Identity Platform (external users) | Canonical Utah user synced from any trusted IdP |
| Decisions | Allow / block at the load balancer (context-aware access: device, IP, geo) | RBAC + `ltree` org inheritance + resource-instance scoping + ABAC (MFA, IP CIDR, time windows) |

The combined request flow:

```text
Browser ──▶ HTTPS Load Balancer ──▶ IAP (authenticates user, signs JWT assertion)
                                        │
                                        ▼
                                   Cloud Run App
                                   pkg/authzclient.IAPTokenExchange middleware
                                        │  POST /v1/auth/token { subject_token: <IAP assertion> }
                                        ▼
                              Utah Common AuthZ Server
                              (verifies IAP signature via Google JWKS, checks audience,
                               resolves/JIT-provisions user, issues app-scoped ES256 JWT)
                                        │  app JWT (aud = your app slug, TTL = app token_ttl_seconds)
                                        ▼
                                   RequirePermission middleware
                                        │  POST /v1/authorize (fine-grained Zero Trust decision)
                                        ▼
                                   Your handler 🎉
```

What makes this work with no custom crypto code:

- IAP signs a JWT assertion into the **`x-goog-iap-jwt-assertion`** header on every request
  with `iss = https://cloud.google.com/iap` and `alg = ES256`.
- Google publishes the verification keys in **standard JWKS format** at
  `https://www.gstatic.com/iap/verify/public_key-jwk`, which the service's multi-issuer
  OIDC verifier consumes natively (`internal/authn/oidc_manager.go`).
- The seeded `google-iap` Identity Provider row (migration `000005`) already points at that
  JWKS URI; you only need to configure your audience and activate it.

---

## 2. Prerequisites on the Google Side

1. Your Cloud Run service must be exposed through an **HTTPS Application Load Balancer with a
   serverless NEG backend** — IAP is enabled on the backend service, not on the Cloud Run
   URL directly. (If you currently use Cloud Run's built-in `--ingress internal-and-cloud-load-balancing`,
   keep it: it complements IAP by blocking direct URL access.)
2. An **OAuth consent screen / brand** configured for the IAP OAuth client.
3. Enable IAP on the backend service and grant your users
   `roles/iap.httpsResourceAccessor` (or use IAP access levels for coarse policy).

```bash
gcloud compute backend-services update BACKEND_SERVICE --global --iap=enabled \
    --oauth2-client-id=IAP_OAUTH_CLIENT_ID \
    --oauth2-client-secret=$(gcloud secrets versions access latest --secret=IAP_OAUTH_SECRET)
```

---

## 3. Find Your IAP JWT Audience

The assertion's `aud` value identifies the protected service. For Cloud Run it is:

```text
/projects/PROJECT_NUMBER/locations/REGION/services/SERVICE_NAME
```

The exact string is shown in the Google Cloud Console under
**IAP → Resources → ⋮ → Signed Header JWT Audience**, or compose it:

```bash
PROJECT_NUMBER=$(gcloud projects describe PROJECT_ID --format="value(projectNumber)")
echo "/projects/${PROJECT_NUMBER}/locations/us-west3/services/water-resources-map"
```

---

## 4. Activate the `google-iap` Identity Provider

Migration `000005_seed_google_iap_idp.up.sql` seeds the IdP row **inactive** with a
placeholder audience. Point it at your real audience and activate it:

```bash
PGPASSWORD="${DB_PASS}" psql -h 127.0.0.1 -p 5433 -U "${DB_USER}" -d "${DB_NAME}" -c "
UPDATE identity_providers
SET client_id = '/projects/PROJECT_NUMBER/locations/us-west3/services/water-resources-map',
    is_active = TRUE
WHERE slug = 'google-iap';"
```

> **Multiple IAP-protected services?** One issuer, many audiences — list them
> comma-separated in `client_id`. The verifier checks that each assertion's `aud` matches at
> least one entry:
>
> ```sql
> SET client_id = '/projects/PN/locations/us-west3/services/water-map,
>                  /projects/PN/locations/us-west3/services/water-models';
> ```

(If your database was initialized before migration `000005`, apply
`migrations/000004_add_google_iap_idp_type.up.sql` and `000005_seed_google_iap_idp.up.sql`
first — see the [Deployment Guide](./DEPLOYMENT_GUIDE.md).)

Then bind the IdP to your application so token exchange is allowed, optionally with a
JIT default role for first-time Google logins:

```bash
curl -X POST https://authz.water.utah.gov/v1/admin/apps/water-resources-map/idps \
  -H "X-Admin-Bootstrap-Key: $ADMIN_BOOTSTRAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"idp_slug": "google-iap", "allow_jit_signup": true, "default_role_id": "<PUBLIC_VIEWER_ROLE_UUID>"}'
```

---

## 5. Wire the Downstream Go SDK

`pkg/authzclient` ships the `IAPTokenExchange` middleware. It reads the signed header,
**verifies its signature locally against Google IAP's published public keys** (fetched from
`https://www.gstatic.com/iap/verify/public_key-jwk`, cached for 5 minutes), exchanges it for
your app's Zero Trust JWT (caching per verified user until shortly before expiry), and injects
it as the Bearer credential so `RequirePermission` works unchanged:

```go
authz := authzclient.NewClient("https://authz.water.utah.gov", "water-resources-map")

protected := authz.IAPTokenExchange(nil)(          // 1. verify + exchange IAP assertion (cached)
	authz.RequirePermission("basin_layer", "read", nil)( // 2. fine-grained Zero Trust check
		mux,                                            // 3. your handlers
	))
```

Behavior notes:

- Requests **without** an IAP header pass through untouched, so direct Bearer callers
  (service-to-service) keep working.
- When the IAP header **is** present, the assertion is signature-verified (ES256/RS256,
  issuer `https://cloud.google.com/iap`, expiry) **before** any cache lookup or exchange,
  and the IAP-verified identity always replaces any client-supplied `Authorization` header.
  A forged assertion — even one carrying another user's `sub` — cannot read that user's
  cached token because it cannot carry a valid Google signature.
- A failed verification or exchange (bad signature, expired assertion, unbound IdP,
  inactive user) returns `401` before your handler runs.
- For non-Go backends, pass the raw `x-goog-iap-jwt-assertion` value as `subject_token` to
  `POST /v1/auth/token` yourself — the REST contract is identical.

---

## 6. External Users via Identity Platform Behind IAP

If your IAP OAuth client uses **Identity Platform** for external users (conservancy
districts, consultants), the assertion carries the `gcip` claim and the top-level
`sub`/`email` are **prefixed** with the Identity Platform issuer/tenant, e.g.
`securetoken.google.com/my-project:external-user@jvwcd.org`. Two implications:

- Users federate on that full prefixed subject — stable, but do not expect the raw email in `sub`.
- Useful attributes (display name, MFA evidence, group claims from the upstream provider)
  live in `gcip.sign_in_attributes`; adjust the IdP row's `claim_mappings` to read them, e.g.
  `'{"sub": "sub", "email": "email", "name": "gcip.sign_in_attributes.displayName",
  "groups": "gcip.sign_in_attributes.groups", "mfa": "gcip.sign_in_second_factor"}'::jsonb`.

**MFA caveat:** plain Google-identity IAP assertions carry no `amr`/MFA claim, so
`mfa` maps to `false`. If an application sets `require_mfa = true`, IAP-authenticated
users will be denied at exchange — enforce MFA at the IAP/Identity Platform layer instead
and leave the app flag off, or map an MFA-evidencing claim from `gcip` as above.

---

## 7. Operations Checklist

- **Key rotation:** Google rotates IAP signing keys periodically; the JWKS endpoint reflects
  current keys and the verifier re-fetches on unknown `kid` automatically. No action needed.
- **Health checks:** LB health checks do not carry JWTs — keep health-check paths
  (e.g. `/healthz`) outside the protected middleware chain.
- **Test your rejection path:** append `?secure_token_test=1` to any URL and IAP will send
  an intentionally invalid JWT — your users should get `401`, never a crash or a pass-through.
- **Defense in depth:** also set Cloud Run ingress to `internal-and-cloud-load-balancing` so
  the service is only reachable through IAP.
- **Auditing:** every exchange writes an `authn.token_exchange` audit row; IAP-side access
  logs land in Cloud Logging under the load balancer resource.
