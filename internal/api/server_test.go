package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/api"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/authn"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/authz"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/db"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
	"github.com/utah-dnr/utah-gcp-common-authz/pkg/authzclient"
)

// mockUpstreamVerifier simulates cryptographic OIDC verification for UtahID & External IdP tokens in tests.
type mockUpstreamVerifier struct {
	tokens map[string]*authn.VerifiedIdentity
}

func (m *mockUpstreamVerifier) VerifyUpstreamToken(_ context.Context, rawToken string) (*authn.VerifiedIdentity, error) {
	id, ok := m.tokens[rawToken]
	if !ok {
		return nil, db.ErrUnauthorized
	}
	return id, nil
}

func TestZeroTrustEndToEndFlow(t *testing.T) {
	store := db.NewMemoryStore()
	verifier := &mockUpstreamVerifier{tokens: make(map[string]*authn.VerifiedIdentity)}

	tokenSvc, err := authn.NewTokenService(store, verifier, "https://authz.utah.gov", "test-key-1", "")
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}

	pdp := authz.NewPDP(store)
	const bootstrapKey = "test-utah-bootstrap-secret"
	srv := api.NewServer(store, tokenSvc, pdp, bootstrapKey)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Register UtahID and External OIDC Identity Providers via Admin API
	var utahIDP domain.IdentityProvider
	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/idps", map[string]any{
		"slug":              "utahid-prod",
		"name":              "State of Utah (UtahID OIDC)",
		"provider_type":     "utahid",
		"issuer_url":        "https://id.utah.gov/oauth2/default",
		"client_id":         "utah-dnr-client",
		"is_internal_state": true,
		"auto_provision":    true,
		"is_active":         true,
	}, http.StatusCreated, &utahIDP)

	var extIDP domain.IdentityProvider
	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/idps", map[string]any{
		"slug":              "external-oidc",
		"name":              "External Water District OIDC",
		"provider_type":     "gcp_identity_platform",
		"issuer_url":        "https://securetoken.google.com/utah-external",
		"client_id":         "utah-external-client",
		"is_internal_state": false,
		"auto_provision":    true,
		"is_active":         true,
	}, http.StatusCreated, &extIDP)

	// 2. Register Hierarchical Organizations (DNR -> DWRe, and external JVWCD)
	var dnrOrg domain.Organization
	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/organizations", map[string]any{
		"slug":           "utah-dnr",
		"name":           "Utah Department of Natural Resources",
		"org_type":       "state_agency",
		"hierarchy_path": "state_of_utah.dnr",
		"is_active":      true,
	}, http.StatusCreated, &dnrOrg)

	var dwreOrg domain.Organization
	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/organizations", map[string]any{
		"slug":           "utah-dnr-dwre",
		"name":           "Utah Division of Water Resources",
		"org_type":       "state_agency",
		"parent_id":      dnrOrg.ID,
		"hierarchy_path": "state_of_utah.dnr.dwre",
		"is_active":      true,
	}, http.StatusCreated, &dwreOrg)

	// 3. Register Application 'water-resources-map'
	var mapApp domain.Application
	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/apps", map[string]any{
		"slug":              "water-resources-map",
		"name":              "Utah Water Resources Map Portal",
		"owner_org_id":      dwreOrg.ID,
		"token_ttl_seconds": 600,
		"require_mfa":       false,
		"is_active":         true,
	}, http.StatusCreated, &mapApp)

	// 4. Register Fine-Grained Permissions for 'water-resources-map'
	var permRead, permWrite, permApprove domain.Permission
	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/apps/water-resources-map/permissions", map[string]any{
		"resource_type": "basin_layer",
		"action":        "read",
		"description":   "Read basin GIS layers",
	}, http.StatusCreated, &permRead)

	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/apps/water-resources-map/permissions", map[string]any{
		"resource_type": "basin_layer",
		"action":        "write",
		"description":   "Edit basin GIS layers",
	}, http.StatusCreated, &permWrite)

	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/apps/water-resources-map/permissions", map[string]any{
		"resource_type": "watershed_model",
		"action":        "approve",
		"description":   "Approve official watershed models",
	}, http.StatusCreated, &permApprove)

	// 5. Register Roles and Bundle Permissions
	var viewerRole, editorRole, hydrologistRole domain.Role
	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/apps/water-resources-map/roles", map[string]any{
		"slug":           "public_viewer",
		"name":           "Public Viewer",
		"permission_ids": []uuid.UUID{permRead.ID},
	}, http.StatusCreated, &viewerRole)

	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/apps/water-resources-map/roles", map[string]any{
		"slug":           "basin_editor",
		"name":           "Scoped Basin Editor",
		"inherits_from":  viewerRole.ID, // Inherits basin_layer:read from public_viewer
		"permission_ids": []uuid.UUID{permWrite.ID},
	}, http.StatusCreated, &editorRole)

	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/apps/water-resources-map/roles", map[string]any{
		"slug":           "senior_hydrologist",
		"name":           "Senior State Hydrologist",
		"inherits_from":  editorRole.ID,
		"permission_ids": []uuid.UUID{permApprove.ID},
	}, http.StatusCreated, &hydrologistRole)

	// Attach MFA & State Network CIDR ABAC condition to watershed_model:approve on senior_hydrologist
	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost,
		"/v1/admin/apps/water-resources-map/roles/senior_hydrologist/permissions",
		map[string]any{
			"permission_id": permApprove.ID,
			"conditions": map[string]any{
				"require_mfa": true,
				"ip_cidrs":    []string{"204.113.0.0/16"},
			},
		}, http.StatusOK, nil)

	// 6. Bind both UtahID and External OIDC IdPs to 'water-resources-map'
	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/apps/water-resources-map/idps", map[string]any{
		"idp_slug":         "utahid-prod",
		"allow_jit_signup": true,
		"default_role_id":  viewerRole.ID,
	}, http.StatusOK, nil)

	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/apps/water-resources-map/idps", map[string]any{
		"idp_slug":         "external-oidc",
		"allow_jit_signup": true,
		"default_role_id":  viewerRole.ID,
	}, http.StatusOK, nil)

	// 7. Simulate UtahID Login & Token Exchange for a State Employee and an External Partner
	verifier.tokens["utahid-token-alice"] = &authn.VerifiedIdentity{
		IdP:           &utahIDP,
		Subject:       "utahid-emp-1001",
		Email:         "alice@utah.gov",
		EmailVerified: true,
		DisplayName:   "Alice Hydrologist",
		MFAVerified:   true,
	}
	verifier.tokens["ext-token-bob"] = &authn.VerifiedIdentity{
		IdP:           &extIDP,
		Subject:       "ext-partner-2002",
		Email:         "bob@jvwcd.org",
		EmailVerified: true,
		DisplayName:   "Bob External Engineer",
		MFAVerified:   false,
	}

	var aliceExchange, bobExchange authn.TokenExchangeResponse
	doAdminRequest(t, ts.URL, "", http.MethodPost, "/v1/auth/token", map[string]any{
		"subject_token": "utahid-token-alice",
		"target_app":    "water-resources-map",
	}, http.StatusOK, &aliceExchange)

	if aliceExchange.User.UserType != "state_employee" {
		t.Fatalf("expected Alice user_type=state_employee, got %s", aliceExchange.User.UserType)
	}

	doAdminRequest(t, ts.URL, "", http.MethodPost, "/v1/auth/token", map[string]any{
		"subject_token": "ext-token-bob",
		"target_app":    "water-resources-map",
	}, http.StatusOK, &bobExchange)

	if bobExchange.User.UserType != "external_partner" {
		t.Fatalf("expected Bob user_type=external_partner, got %s", bobExchange.User.UserType)
	}

	// 8. Assign Scoped Roles:
	// - Alice gets 'senior_hydrologist' at parent org 'utah-dnr' (inherits down to 'utah-dnr-dwre')
	// - Bob gets 'basin_editor' ONLY for specific resource_id 'jordan-river-basin'
	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/apps/water-resources-map/assignments", map[string]any{
		"role_slug":          "senior_hydrologist",
		"principal_type":     "user",
		"user_id":            aliceExchange.User.ID,
		"effect":             "allow",
		"organization_id":    dnrOrg.ID,
		"include_child_orgs": true,
		"justification":      "Lead hydrologist for DNR divisions",
	}, http.StatusCreated, nil)

	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/apps/water-resources-map/assignments", map[string]any{
		"role_slug":      "basin_editor",
		"principal_type": "user",
		"user_id":        bobExchange.User.ID,
		"effect":         "allow",
		"resource_type":  "basin_layer",
		"resource_id":    "jordan-river-basin",
		"justification":  "External consultant for Jordan River Basin study",
	}, http.StatusCreated, nil)

	// 9. Verify Fine-Grained Zero Trust Authorization checks via /v1/authorize
	// Case A: Bob can write to 'jordan-river-basin'
	var decision domain.AuthorizeResponse
	doAdminRequest(t, ts.URL, "", http.MethodPost, "/v1/authorize", domain.AuthorizeRequest{
		PrincipalID:  bobExchange.User.ID,
		AppSlug:      "water-resources-map",
		ResourceType: "basin_layer",
		ResourceID:   "jordan-river-basin",
		Action:       "write",
	}, http.StatusOK, &decision)
	if !decision.Allowed {
		t.Fatalf("expected Bob to be allowed write on jordan-river-basin, got deny: %s", decision.Reason)
	}

	// Case B: Bob is DENIED write on 'bear-river-basin' (Zero Trust resource isolation)
	doAdminRequest(t, ts.URL, "", http.MethodPost, "/v1/authorize", domain.AuthorizeRequest{
		PrincipalID:  bobExchange.User.ID,
		AppSlug:      "water-resources-map",
		ResourceType: "basin_layer",
		ResourceID:   "bear-river-basin",
		Action:       "write",
	}, http.StatusOK, &decision)
	if decision.Allowed {
		t.Fatalf("expected Bob to be denied write on bear-river-basin")
	}

	// Case C: Alice can approve watershed models in child org 'utah-dnr-dwre' when on State CIDR + MFA
	doAdminRequest(t, ts.URL, "", http.MethodPost, "/v1/authorize", domain.AuthorizeRequest{
		PrincipalID:    aliceExchange.User.ID,
		AppSlug:        "water-resources-map",
		ResourceType:   "watershed_model",
		ResourceID:     "model-2026-q4",
		Action:         "approve",
		OrganizationID: &dwreOrg.ID,
		Context: domain.RequestContext{
			ClientIP:    "204.113.42.19",
			MFAVerified: true,
		},
	}, http.StatusOK, &decision)
	if !decision.Allowed {
		t.Fatalf("expected Alice to be allowed watershed_model:approve on state network with MFA, got: %s", decision.Reason)
	}

	// Case D: Alice is DENIED watershed_model:approve when connecting from an untrusted IP outside 204.113.0.0/16
	doAdminRequest(t, ts.URL, "", http.MethodPost, "/v1/authorize", domain.AuthorizeRequest{
		PrincipalID:    aliceExchange.User.ID,
		AppSlug:        "water-resources-map",
		ResourceType:   "watershed_model",
		ResourceID:     "model-2026-q4",
		Action:         "approve",
		OrganizationID: &dwreOrg.ID,
		Context: domain.RequestContext{
			ClientIP:    "198.51.100.77",
			MFAVerified: true,
		},
	}, http.StatusOK, &decision)
	if decision.Allowed || decision.Reason != "abac_condition_failed:client_ip_outside_allowed_cidrs" {
		t.Fatalf("expected CIDR ABAC denial, got allowed=%v reason=%s", decision.Allowed, decision.Reason)
	}

	// Case E: Explicit DENY rule immediately overrides Bob's write access on 'jordan-river-basin'
	doAdminRequest(t, ts.URL, bootstrapKey, http.MethodPost, "/v1/admin/apps/water-resources-map/assignments", map[string]any{
		"role_slug":      "basin_editor",
		"principal_type": "user",
		"user_id":        bobExchange.User.ID,
		"effect":         "deny",
		"resource_type":  "basin_layer",
		"resource_id":    "jordan-river-basin",
		"justification":  "Freeze edits during annual audit",
	}, http.StatusCreated, nil)

	doAdminRequest(t, ts.URL, "", http.MethodPost, "/v1/authorize", domain.AuthorizeRequest{
		PrincipalID:  bobExchange.User.ID,
		AppSlug:      "water-resources-map",
		ResourceType: "basin_layer",
		ResourceID:   "jordan-river-basin",
		Action:       "write",
	}, http.StatusOK, &decision)
	if decision.Allowed || decision.Reason != "explicit_deny_rule" {
		t.Fatalf("expected explicit_deny_rule to override allow grant, got allowed=%v reason=%s", decision.Allowed, decision.Reason)
	}

	// 10. Verify Downstream Go SDK Middleware (pkg/authzclient)
	sdkClient := authzclient.NewClient(ts.URL, "water-resources-map")
	protectedApp := sdkClient.RequirePermission("basin_layer", "read", func(r *http.Request) string {
		return r.URL.Query().Get("basin")
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := authzclient.PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello " + principal.Email))
	}))

	req := httptest.NewRequest(http.MethodGet, "/map?basin=utah-lake", nil)
	req.Header.Set("Authorization", "Bearer "+aliceExchange.AccessToken)
	rec := httptest.NewRecorder()
	protectedApp.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected downstream SDK middleware to allow Alice basin_layer:read, got status %d", rec.Code)
	}
}

// TestGoogleIAPAssertionExchange registers a Google Identity-Aware Proxy IdP with
// multiple comma-separated service audiences and verifies the full exchange flow.
func TestGoogleIAPAssertionExchange(t *testing.T) {
	store := db.NewMemoryStore()
	verifier := &mockUpstreamVerifier{tokens: make(map[string]*authn.VerifiedIdentity)}

	tokenSvc, err := authn.NewTokenService(store, verifier, "https://authz.utah.gov", "test-key-1", "")
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}

	srv := api.NewServer(store, tokenSvc, authz.NewPDP(store), "test-utah-bootstrap-secret")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Register the IAP IdP: one issuer, two accepted Cloud Run service audiences
	var iapIDP domain.IdentityProvider
	doAdminRequest(t, ts.URL, "test-utah-bootstrap-secret", http.MethodPost, "/v1/admin/idps", map[string]any{
		"slug":           "google-iap",
		"name":           "Google Cloud Identity-Aware Proxy (IAP)",
		"provider_type":  "google_iap",
		"issuer_url":     domain.IAPIssuerURL,
		"client_id":      "/projects/123456789/locations/us-west3/services/water-map, /projects/123456789/locations/us-west3/services/water-models",
		"jwks_uri":       domain.IAPJWKSURI,
		"auto_provision": true,
		"is_active":      true,
	}, http.StatusCreated, &iapIDP)

	// 2. Create one app that trusts IAP and one that does not
	doAdminRequest(t, ts.URL, "test-utah-bootstrap-secret", http.MethodPost, "/v1/admin/apps", map[string]any{
		"slug": "water-map", "name": "IAP-Protected Water Map", "is_active": true,
	}, http.StatusCreated, nil)
	doAdminRequest(t, ts.URL, "test-utah-bootstrap-secret", http.MethodPost, "/v1/admin/apps", map[string]any{
		"slug": "internal-tool", "name": "Internal Tool (no IAP binding)", "is_active": true,
	}, http.StatusCreated, nil)

	doAdminRequest(t, ts.URL, "test-utah-bootstrap-secret", http.MethodPost, "/v1/admin/apps/water-map/idps", map[string]any{
		"idp_slug": "google-iap",
	}, http.StatusOK, nil)

	// 3. Simulate a Google IAP signed-header assertion verified by the (mocked) OIDC verifier
	verifier.tokens["iap-assertion-carol"] = &authn.VerifiedIdentity{
		IdP:           &iapIDP,
		Subject:       "accounts.google.com:carol@utah.gov",
		Email:         "carol@utah.gov",
		EmailVerified: true,
		DisplayName:   "Carol State Planner",
		MFAVerified:   false,
	}

	var carolExchange authn.TokenExchangeResponse
	doAdminRequest(t, ts.URL, "", http.MethodPost, "/v1/auth/token", map[string]any{
		"subject_token": "iap-assertion-carol",
		"target_app":    "water-map",
	}, http.StatusOK, &carolExchange)

	if carolExchange.User.Email != "carol@utah.gov" {
		t.Fatalf("expected IAP identity carol@utah.gov, got %s", carolExchange.User.Email)
	}
	if len(carolExchange.AccessToken) == 0 {
		t.Fatal("expected non-empty exchanged access token for IAP assertion")
	}

	// 4. Exchange against an application that has NOT bound the IAP IdP must be rejected
	doAdminRequest(t, ts.URL, "", http.MethodPost, "/v1/auth/token", map[string]any{
		"subject_token": "iap-assertion-carol",
		"target_app":    "internal-tool",
	}, http.StatusUnauthorized, nil)
}

func doAdminRequest(t *testing.T, baseURL, bootstrapKey, method, path string, body any, wantStatus int, out any) {
	t.Helper()
	var reqBody *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, baseURL+path, reqBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bootstrapKey != "" {
		req.Header.Set("X-Admin-Bootstrap-Key", bootstrapKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http do %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != wantStatus {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("%s %s: got status %d, want %d (body: %v)", method, path, resp.StatusCode, wantStatus, errBody)
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode response from %s %s: %v", method, path, err)
		}
	}
}
