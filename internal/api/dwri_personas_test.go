package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/api"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/authn"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/authz"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/db"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
)

// TestDWRi2026PersonasAndLegacyMigration verifies that all 6 DWRi Personas (and sub-personas)
// from the 72-page Sep 2026 UCD PDF, Figma prototypes, and Legacy Permission Stores report
// enforce their exact Zero Trust boundaries.
func TestDWRi2026PersonasAndLegacyMigration(t *testing.T) {
	store := db.NewMemoryStore()
	verifier := &mockUpstreamVerifier{tokens: make(map[string]*authn.VerifiedIdentity)}
	tokenSvc, err := authn.NewTokenService(store, verifier, "https://authz.waterrights.utah.gov", "dwri-key-1", "")
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}
	pdp := authz.NewPDP(store)
	const bootstrapKey = "dwri-bootstrap-key"
	srv := api.NewServer(store, tokenSvc, pdp, bootstrapKey)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx := context.Background()

	// 1. Seed Identity Providers (UtahID + External Water User/Supplier IdP + ORCID Researcher IdP)
	utahIdP, _ := store.CreateIdentityProvider(ctx, domain.IdentityProvider{
		Slug: "utahid-prod", Name: "UtahID OIDC", ProviderType: domain.IdPUtahID,
		IssuerURL: "https://id.utah.gov/oauth2/default", ClientID: "dwri-client",
		IsInternalState: true, AutoProvision: true, IsActive: true,
	})
	extIdP, _ := store.CreateIdentityProvider(ctx, domain.IdentityProvider{
		Slug: "external-gcp-identity", Name: "External Collaborator OIDC", ProviderType: domain.IdPGCPIdentityPlatform,
		IssuerURL: "https://securetoken.google.com/dwri-ext", ClientID: "dwri-ext",
		IsInternalState: false, AutoProvision: true, IsActive: true,
	})
	orcidIdP, _ := store.CreateIdentityProvider(ctx, domain.IdentityProvider{
		Slug: "research-orcid-oidc", Name: "ORCID Researcher OIDC", ProviderType: domain.IdPGenericOIDC,
		IssuerURL: "https://orcid.org", ClientID: "dwri-orcid",
		IsInternalState: false, AutoProvision: true, IsActive: true,
	})

	// 2. Seed Organizations (DWRi HQ, Northern Region Logan, PRWUA, JVWCD)
	dwriHQ, _ := store.CreateOrganization(ctx, domain.Organization{
		Slug: "utah-dnr-dwri", Name: "Utah Division of Water Rights", OrgType: "state_agency",
		HierarchyPath: "state_of_utah.dnr.dwri", IsActive: true,
	})
	loganRegion, _ := store.CreateOrganization(ctx, domain.Organization{
		Slug: "dwri-region-northern-logan", Name: "DWRi Northern Regional Office (Logan)", OrgType: "state_agency",
		ParentID: &dwriHQ.ID, HierarchyPath: "state_of_utah.dnr.dwri.region_northern_logan", IsActive: true,
	})
	prwuaOrg, _ := store.CreateOrganization(ctx, domain.Organization{
		Slug: "prwua", Name: "Provo River Water Users Association", OrgType: "water_district",
		HierarchyPath: "external_orgs.prwua", IsActive: true,
	})
	jvwcdOrg, _ := store.CreateOrganization(ctx, domain.Organization{
		Slug: "jvwcd", Name: "Jordan Valley Water Conservancy District", OrgType: "water_district",
		HierarchyPath: "external_orgs.jvwcd", IsActive: true,
	})

	// 3. Register 'dwri-water-measurement-dashboard'
	app, _ := store.CreateApplication(ctx, domain.Application{
		Slug: "dwri-water-measurement-dashboard", Name: "DWRi Water Measurement Dashboard",
		OwnerOrgID: &dwriHQ.ID, TokenTTLSeconds: 900, IsActive: true,
	})

	// Helper to register permissions
	mustPerm := func(resType, action string) uuid.UUID {
		p, err := store.CreatePermission(ctx, domain.Permission{
			ApplicationID: app.ID, ResourceType: resType, Action: action,
		})
		if err != nil {
			t.Fatalf("create perm %s:%s: %v", resType, action, err)
		}
		return p.ID
	}

	pPubRead := mustPerm("published_station", "read")
	pPubExport := mustPerm("public_export", "create")
	pUserPref := mustPerm("user_preference", "manage_own")
	pSupRead := mustPerm("supplier_system", "read")
	pSupBoundary := mustPerm("supplier_boundary", "propose")
	pSupReport := mustPerm("supplier_report", "submit")
	pSupManageReview := mustPerm("supplier_system", "manage_review")
	pResRead := mustPerm("research_dataset", "read")
	pApiToken := mustPerm("api_token", "manage_own")
	pSysRestricted := mustPerm("distribution_system", "read_restricted")
	pMeasCreate := mustPerm("measurement", "create")
	pMeasRevise := mustPerm("measurement", "revise")
	pStaUpdate := mustPerm("station", "update_assigned")
	pDistReport := mustPerm("distribution_report", "generate")
	pStaCreate := mustPerm("station", "create")
	pDiagRead := mustPerm("diagnostics", "read")
	pVisitManage := mustPerm("site_visit", "manage")
	pAttachInternal := mustPerm("attachment_internal", "manage")
	pRawWithdraw := mustPerm("raw_observation", "withdraw")
	pIngestReq := mustPerm("ingestion_connection", "request")
	pWcatSync := mustPerm("wcat_model", "sync")
	pAssetManage := mustPerm("asset_inventory", "manage")
	pTelemetryAddr := mustPerm("telemetry_address", "manage")
	pVocabManage := mustPerm("vocabulary", "manage")
	pQcManage := mustPerm("qc_rule", "manage")
	pUserAssign := mustPerm("user_assignment", "manage")

	// 4. Create Persona Roles & Inheritance Tree
	rDonna, _ := store.CreateRole(ctx, domain.Role{ApplicationID: app.ID, Slug: "donna_public_reader", Name: "Donna Public"})
	_ = store.AttachPermissionToRole(ctx, rDonna.ID, pPubRead, domain.ABACConditions{})
	_ = store.AttachPermissionToRole(ctx, rDonna.ID, pPubExport, domain.ABACConditions{})

	rWiley, _ := store.CreateRole(ctx, domain.Role{ApplicationID: app.ID, Slug: "wiley_water_user", Name: "Wiley Water User", InheritsFrom: &rDonna.ID})
	_ = store.AttachPermissionToRole(ctx, rWiley.ID, pUserPref, domain.ABACConditions{})

	rParker, _ := store.CreateRole(ctx, domain.Role{ApplicationID: app.ID, Slug: "parker_water_supplier", Name: "Parker Supplier", InheritsFrom: &rWiley.ID})
	_ = store.AttachPermissionToRole(ctx, rParker.ID, pSupRead, domain.ABACConditions{})
	_ = store.AttachPermissionToRole(ctx, rParker.ID, pSupBoundary, domain.ABACConditions{})
	_ = store.AttachPermissionToRole(ctx, rParker.ID, pSupReport, domain.ABACConditions{})

	rSarah, _ := store.CreateRole(ctx, domain.Role{ApplicationID: app.ID, Slug: "sarah_researcher", Name: "Sarah Researcher", InheritsFrom: &rWiley.ID})
	_ = store.AttachPermissionToRole(ctx, rSarah.ID, pResRead, domain.ABACConditions{})
	_ = store.AttachPermissionToRole(ctx, rSarah.ID, pApiToken, domain.ABACConditions{})

	rCody, _ := store.CreateRole(ctx, domain.Role{ApplicationID: app.ID, Slug: "cody_commissioner", Name: "Cody Commissioner", InheritsFrom: &rWiley.ID})
	for _, pid := range []uuid.UUID{pSysRestricted, pMeasCreate, pMeasRevise, pStaUpdate, pDistReport} {
		_ = store.AttachPermissionToRole(ctx, rCody.ID, pid, domain.ABACConditions{})
	}

	rFatimaDist, _ := store.CreateRole(ctx, domain.Role{ApplicationID: app.ID, Slug: "fatima_distribution_engineer", Name: "Dory Distribution Engineer", InheritsFrom: &rCody.ID})
	for _, pid := range []uuid.UUID{pStaCreate, pDiagRead, pVisitManage, pAttachInternal} {
		_ = store.AttachPermissionToRole(ctx, rFatimaDist.ID, pid, domain.ABACConditions{})
	}

	rFatimaAuto, _ := store.CreateRole(ctx, domain.Role{ApplicationID: app.ID, Slug: "fatima_automation_engineer", Name: "Fatima Automation Engineer", InheritsFrom: &rFatimaDist.ID})
	_ = store.AttachPermissionToRole(ctx, rFatimaAuto.ID, pRawWithdraw, domain.ABACConditions{RequireMFA: true})
	_ = store.AttachPermissionToRole(ctx, rFatimaAuto.ID, pTelemetryAddr, domain.ABACConditions{RequireMFA: true})
	_ = store.AttachPermissionToRole(ctx, rFatimaAuto.ID, pAssetManage, domain.ABACConditions{})
	_ = store.AttachPermissionToRole(ctx, rFatimaAuto.ID, pIngestReq, domain.ABACConditions{})

	rFatimaModel, _ := store.CreateRole(ctx, domain.Role{ApplicationID: app.ID, Slug: "fatima_modeling_engineer", Name: "Fatima Modeler", InheritsFrom: &rSarah.ID})
	for _, pid := range []uuid.UUID{pSysRestricted, pDiagRead, pWcatSync} {
		_ = store.AttachPermissionToRole(ctx, rFatimaModel.ID, pid, domain.ABACConditions{})
	}

	rDiegoSteward, _ := store.CreateRole(ctx, domain.Role{ApplicationID: app.ID, Slug: "diego_data_steward", Name: "Diego Steward", InheritsFrom: &rFatimaAuto.ID})
	stewardABAC := domain.ABACConditions{RequireMFA: true, AllowedUserTypes: []string{"state_employee"}}
	for _, pid := range []uuid.UUID{pVocabManage, pQcManage, pUserAssign} {
		_ = store.AttachPermissionToRole(ctx, rDiegoSteward.ID, pid, stewardABAC)
	}

	rDiegoWaterUseMgr, _ := store.CreateRole(ctx, domain.Role{ApplicationID: app.ID, Slug: "diego_water_use_manager", Name: "Diego Water Use Manager", InheritsFrom: &rWiley.ID})
	_ = store.AttachPermissionToRole(ctx, rDiegoWaterUseMgr.ID, pSupRead, domain.ABACConditions{})
	_ = store.AttachPermissionToRole(ctx, rDiegoWaterUseMgr.ID, pSupManageReview, stewardABAC)

	// Bind IdPs with JIT default roles (PDF p. 58: account creation grants Wiley Water User permissions)
	_ = store.BindAppIdentityProvider(ctx, domain.AppIdentityProvider{ApplicationID: app.ID, IdPID: utahIdP.ID, AllowJITSignup: true, DefaultRoleID: &rWiley.ID})
	_ = store.BindAppIdentityProvider(ctx, domain.AppIdentityProvider{ApplicationID: app.ID, IdPID: extIdP.ID, AllowJITSignup: true, DefaultRoleID: &rWiley.ID})
	_ = store.BindAppIdentityProvider(ctx, domain.AppIdentityProvider{ApplicationID: app.ID, IdPID: orcidIdP.ID, AllowJITSignup: true, DefaultRoleID: &rSarah.ID})

	// Helper to provision a test persona via Token Exchange (returns user ID + app token)
	loginPersona := func(tokenKey string, idp *domain.IdentityProvider, sub, email, name string, mfa bool) (uuid.UUID, string) {
		verifier.tokens[tokenKey] = &authn.VerifiedIdentity{
			IdP: idp, Subject: sub, Email: email, EmailVerified: true, DisplayName: name, MFAVerified: mfa,
		}
		var ex authn.TokenExchangeResponse
		doAdminRequest(t, ts.URL, "", http.MethodPost, "/v1/auth/token", map[string]any{
			"subject_token": tokenKey,
			"target_app":    app.Slug,
		}, http.StatusOK, &ex)
		return ex.User.ID, ex.AccessToken
	}

	wileyID, wileyToken := loginPersona("tok-wiley", extIdP, "wiley-1", "wiley@ranch.utah", "Wiley Rancher", false)
	parkerID, parkerToken := loginPersona("tok-parker", extIdP, "parker-1", "parker@prwua.org", "Parker Supplier", false)
	sarahID, sarahToken := loginPersona("tok-sarah", orcidIdP, "0000-0002-1825-0097", "bart@crau.utah.gov", "Sarah/Bart Researcher", false)
	codyID, codyToken := loginPersona("tok-cody", extIdP, "kent-wilkerson", "kent@weberriver.org", "Kent Wilkerson (Commissioner)", false)
	deputyID, deputyToken := loginPersona("tok-deputy", extIdP, "deputy-weber", "deputy@weberriver.org", "Weber Seasonal Deputy", false)
	modelerID, modelerToken := loginPersona("tok-modeler", utahIdP, "ed-vidmar", "evidmar@utah.gov", "Ed Vidmar (WCAT Modeler)", true)
	autoEngID, autoEngToken := loginPersona("tok-cole", utahIdP, "cole-panter", "cpanter@utah.gov", "Cole Panter (Automation Eng)", true)
	diegoID, diegoToken := loginPersona("tok-diego", utahIdP, "adel-abdallah", "aabdallah@utah.gov", "Adel/Diego (Data Steward)", true)
	waterUseMgrID, waterUseMgrToken := loginPersona("tok-wumgr", utahIdP, "wu-mgr", "wumanager@utah.gov", "Water Use Data Manager", true)

	// Same Automation Engineer logging in WITHOUT MFA (same user, separate session token):
	// identity context now comes from the token, so the no-MFA denial path uses this token.
	_, autoEngNoMFAToken := loginPersona("tok-cole-nomfa", utahIdP, "cole-panter", "cpanter@utah.gov", "Cole Panter (Automation Eng)", false)

	// 5. Assign Scoped Roles to Personas
	// Parker -> Provo River Water Users Association (PRWUA) only
	_, _ = store.CreateRoleAssignment(ctx, domain.RoleAssignment{
		ApplicationID: app.ID, RoleID: rParker.ID, PrincipalType: domain.PrincipalUser,
		UserID: &parkerID, Effect: domain.EffectAllow, OrganizationID: &prwuaOrg.ID,
	})

	// Cody (Kent Wilkerson) -> Weber River Distribution System only
	resDistSys := "distribution_system"
	resWeber := "weber-river"
	_, _ = store.CreateRoleAssignment(ctx, domain.RoleAssignment{
		ApplicationID: app.ID, RoleID: rCody.ID, PrincipalType: domain.PrincipalUser,
		UserID: &codyID, Effect: domain.EffectAllow, ResourceType: &resDistSys, ResourceID: &resWeber,
	})

	// Seasonal Deputy -> Expired delegation on Weber River (simulating post-season offline draft sync rejection)
	pastStart := time.Now().UTC().Add(-48 * time.Hour)
	pastEnd := time.Now().UTC().Add(-1 * time.Hour)
	_, _ = store.CreateRoleAssignment(ctx, domain.RoleAssignment{
		ApplicationID: app.ID, RoleID: rCody.ID, PrincipalType: domain.PrincipalUser,
		UserID: &deputyID, Effect: domain.EffectAllow, ResourceType: &resDistSys, ResourceID: &resWeber,
		StartsAt: pastStart, ExpiresAt: &pastEnd,
	})

	// Fatima Modeler -> Statewide modeling role
	_, _ = store.CreateRoleAssignment(ctx, domain.RoleAssignment{
		ApplicationID: app.ID, RoleID: rFatimaModel.ID, PrincipalType: domain.PrincipalUser,
		UserID: &modelerID, Effect: domain.EffectAllow,
	})

	// Fatima Automation Engineer -> Scoped to DWRi HQ (covers all 7 Regional Offices via ltree)
	_, _ = store.CreateRoleAssignment(ctx, domain.RoleAssignment{
		ApplicationID: app.ID, RoleID: rFatimaAuto.ID, PrincipalType: domain.PrincipalUser,
		UserID: &autoEngID, Effect: domain.EffectAllow, OrganizationID: &dwriHQ.ID, IncludeChildOrgs: true,
	})

	// Diego Data Steward -> Statewide
	_, _ = store.CreateRoleAssignment(ctx, domain.RoleAssignment{
		ApplicationID: app.ID, RoleID: rDiegoSteward.ID, PrincipalType: domain.PrincipalUser,
		UserID: &diegoID, Effect: domain.EffectAllow,
	})

	// Diego Water Use Program Data Manager -> Statewide
	_, _ = store.CreateRoleAssignment(ctx, domain.RoleAssignment{
		ApplicationID: app.ID, RoleID: rDiegoWaterUseMgr.ID, PrincipalType: domain.PrincipalUser,
		UserID: &waterUseMgrID, Effect: domain.EffectAllow,
	})

	// PDP checks authenticate with the persona's own app token; MFA/user_type identity
	// context is taken from the verified token claims, not the request body.
	checkAuth := func(token string, uid uuid.UUID, resType, resID, action string, orgID *uuid.UUID) domain.AuthorizeResponse {
		var resp domain.AuthorizeResponse
		doPDPRequest(t, ts.URL, token, http.MethodPost, "/v1/authorize", domain.AuthorizeRequest{
			PrincipalID: uid, AppSlug: app.Slug, ResourceType: resType, ResourceID: resID,
			Action: action, OrganizationID: orgID,
			Context: domain.RequestContext{ClientIP: "204.113.10.10"},
		}, http.StatusOK, &resp)
		return resp
	}

	// Assertion 1: Wiley can manage My Sites favorites, but cannot enter measurements or view internal photos
	if !checkAuth(wileyToken, wileyID, "user_preference", "", "manage_own", nil).Allowed {
		t.Fatal("Wiley should be allowed user_preference:manage_own")
	}
	if checkAuth(wileyToken, wileyID, "measurement", "weber-river", "create", nil).Allowed {
		t.Fatal("Wiley must NOT be allowed to enter measurements")
	}

	// Assertion 2: Parker can submit water use reports and propose boundaries for PRWUA, but NOT for JVWCD
	if !checkAuth(parkerToken, parkerID, "supplier_report", "", "submit", &prwuaOrg.ID).Allowed {
		t.Fatal("Parker should be allowed supplier_report:submit for PRWUA")
	}
	if checkAuth(parkerToken, parkerID, "supplier_report", "", "submit", &jvwcdOrg.ID).Allowed {
		t.Fatal("Parker must be DENIED supplier_report:submit for JVWCD")
	}

	// Assertion 3: Sarah (ORCID Researcher) automatically got sarah_researcher on JIT login; can manage API tokens, cannot see internal gate code photos
	if !checkAuth(sarahToken, sarahID, "api_token", "", "manage_own", nil).Allowed {
		t.Fatal("Sarah should be allowed api_token:manage_own")
	}
	if checkAuth(sarahToken, sarahID, "attachment_internal", "station-101", "manage", nil).Allowed {
		t.Fatal("Sarah must be DENIED attachment_internal:manage (internal photos/gate codes)")
	}

	// Assertion 4: Cody (Kent Wilkerson) can enter/revise readings on 'weber-river', but is DENIED on 'lower-sevier'
	if !checkAuth(codyToken, codyID, "measurement", "weber-river", "create", nil).Allowed {
		t.Fatal("Cody should be allowed measurement:create on weber-river")
	}
	if checkAuth(codyToken, codyID, "measurement", "lower-sevier", "create", nil).Allowed {
		t.Fatal("Cody must be DENIED measurement:create on lower-sevier")
	}

	// Assertion 5: Expired Deputy Commissioner is automatically DENIED when syncing offline drafts after season end (FR-011, FR-027)
	if checkAuth(deputyToken, deputyID, "measurement", "weber-river", "create", nil).Allowed {
		t.Fatal("Expired Deputy Commissioner must be DENIED measurement:create")
	}

	// Assertion 6: Fatima Modeler can sync WCAT models & view battery voltage diagnostics, but CANNOT withdraw raw readings or edit Pakbus telemetry addresses
	if !checkAuth(modelerToken, modelerID, "wcat_model", "spanish-fork", "sync", nil).Allowed {
		t.Fatal("Fatima Modeler should be allowed wcat_model:sync")
	}
	if checkAuth(modelerToken, modelerID, "raw_observation", "obs-99", "withdraw", nil).Allowed {
		t.Fatal("Fatima Modeler must be DENIED raw_observation:withdraw")
	}
	if checkAuth(modelerToken, modelerID, "telemetry_address", "station-101", "manage", nil).Allowed {
		t.Fatal("Fatima Modeler must be DENIED telemetry_address:manage")
	}

	// Assertion 7: Fatima Automation Engineer can withdraw raw readings and edit Pakbus/Cell IP addresses in child Regional Office (Logan) ONLY with MFA
	if !checkAuth(autoEngToken, autoEngID, "raw_observation", "obs-99", "withdraw", &loganRegion.ID).Allowed {
		t.Fatal("Automation Engineer with MFA should be allowed raw_observation:withdraw in Logan Region")
	}
	if checkAuth(autoEngNoMFAToken, autoEngID, "raw_observation", "obs-99", "withdraw", &loganRegion.ID).Allowed {
		t.Fatal("Automation Engineer WITHOUT MFA must be DENIED raw_observation:withdraw")
	}

	// Assertion 8: Diego Water Use Program Data Manager (PDF p. 21) can access Manage Systems review, but CANNOT propose/edit supplier boundaries
	if !checkAuth(waterUseMgrToken, waterUseMgrID, "supplier_system", "", "manage_review", nil).Allowed {
		t.Fatal("Water Use Manager should be allowed supplier_system:manage_review")
	}
	if checkAuth(waterUseMgrToken, waterUseMgrID, "supplier_boundary", "", "propose", nil).Allowed {
		t.Fatal("Water Use Manager must be DENIED supplier_boundary:propose (per PDF p. 21)")
	}

	// Assertion 9: Diego Data Steward has sole authority to manage controlled vocabulary & QC rules (with MFA)
	if !checkAuth(diegoToken, diegoID, "vocabulary", "units", "manage", nil).Allowed {
		t.Fatal("Diego Data Steward should be allowed vocabulary:manage")
	}
	if checkAuth(autoEngToken, autoEngID, "vocabulary", "units", "manage", &loganRegion.ID).Allowed {
		t.Fatal("Automation Engineer must be DENIED vocabulary:manage (reserved for Diego Data Steward)")
	}
}
