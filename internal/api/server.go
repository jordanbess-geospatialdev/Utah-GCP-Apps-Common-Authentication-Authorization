package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/authn"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/authz"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/db"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
)

const AdminAppSlug = "utah-iam-admin"

// Server exposes the HTTP REST endpoints for Token Exchange, Zero Trust PDP, and Admin Registration.
type Server struct {
	store             db.Store
	tokenSvc          *authn.TokenService
	pdp               *authz.PDP
	adminBootstrapKey string
	mux               *http.ServeMux
}

// NewServer constructs and wires all routes for the Utah Common AuthN/AuthZ service.
func NewServer(
	store db.Store,
	tokenSvc *authn.TokenService,
	pdp *authz.PDP,
	adminBootstrapKey string,
) *Server {
	s := &Server{
		store:             store,
		tokenSvc:          tokenSvc,
		pdp:               pdp,
		adminBootstrapKey: adminBootstrapKey,
		mux:               http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// Handler returns the root http.Handler with security headers and JSON recovery.
func (s *Server) Handler() http.Handler {
	return s.withSecurityHeaders(s.mux)
}

func (s *Server) registerRoutes() {
	// 1. Health & OIDC/JWKS Discovery
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)

	// 2. Authentication & RFC 8693 Token Exchange
	s.mux.HandleFunc("POST /v1/auth/token", s.handleTokenExchange)

	// 3. Zero Trust Policy Decision Point (PDP)
	s.mux.HandleFunc("POST /v1/authorize", s.handleAuthorize)
	s.mux.HandleFunc("POST /v1/authorize/batch", s.handleBatchAuthorize)

	// 4. Admin Registration & Policy Management API
	s.mux.HandleFunc("GET /v1/admin/idps", s.requireAdmin("idp", "read", s.handleListIdPs))
	s.mux.HandleFunc("POST /v1/admin/idps", s.requireAdmin("idp", "manage", s.handleCreateIdP))

	s.mux.HandleFunc("GET /v1/admin/organizations", s.requireAdmin("organization", "read", s.handleListOrganizations))
	s.mux.HandleFunc("POST /v1/admin/organizations", s.requireAdmin("organization", "manage", s.handleCreateOrganization))

	s.mux.HandleFunc("POST /v1/admin/groups", s.requireAdmin("group", "manage", s.handleCreateGroup))
	s.mux.HandleFunc("POST /v1/admin/groups/{groupID}/members", s.requireAdmin("group", "manage", s.handleAddGroupMember))

	s.mux.HandleFunc("GET /v1/admin/users", s.requireAdmin("user", "read", s.handleListUsers))

	s.mux.HandleFunc("GET /v1/admin/apps", s.requireAdmin("application", "read", s.handleListApps))
	s.mux.HandleFunc("POST /v1/admin/apps", s.requireAdmin("application", "manage", s.handleCreateApp))
	s.mux.HandleFunc("POST /v1/admin/apps/{appSlug}/idps", s.requireAdmin("application", "manage", s.handleBindAppIdP))

	s.mux.HandleFunc("GET /v1/admin/apps/{appSlug}/permissions", s.requireAdmin("application", "read", s.handleListPermissions))
	s.mux.HandleFunc("POST /v1/admin/apps/{appSlug}/permissions", s.requireAdmin("application", "manage", s.handleCreatePermission))

	s.mux.HandleFunc("GET /v1/admin/apps/{appSlug}/roles", s.requireAdmin("application", "read", s.handleListRoles))
	s.mux.HandleFunc("POST /v1/admin/apps/{appSlug}/roles", s.requireAdmin("application", "manage", s.handleCreateRole))
	s.mux.HandleFunc("POST /v1/admin/apps/{appSlug}/roles/{roleSlug}/permissions", s.requireAdmin("application", "manage", s.handleAttachPermissionToRole))

	s.mux.HandleFunc("GET /v1/admin/apps/{appSlug}/assignments", s.requireAdmin("assignment", "read", s.handleListAssignments))
	s.mux.HandleFunc("POST /v1/admin/apps/{appSlug}/assignments", s.requireAdmin("assignment", "manage", s.handleCreateAssignment))
	s.mux.HandleFunc("DELETE /v1/admin/apps/{appSlug}/assignments/{assignmentID}", s.requireAdmin("assignment", "manage", s.handleDeleteAssignment))
}

// ============================================================================
// Health, Discovery & Token Exchange Handlers
// ============================================================================

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "utah-common-authn-authz",
		"time":    time.Now().UTC(),
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, s.tokenSvc.PublicJWKS())
}

func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	var req authn.TokenExchangeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	req.ClientIP = extractClientIP(r)

	resp, err := s.tokenSvc.ExchangeToken(r.Context(), req)
	if err != nil {
		status := http.StatusUnauthorized
		if errors.Is(err, db.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ============================================================================
// Zero Trust Policy Decision Point (PDP) Handlers
// ============================================================================

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var req domain.AuthorizeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.PrincipalID == uuid.Nil || req.AppSlug == "" || req.ResourceType == "" || req.Action == "" {
		writeError(w, http.StatusBadRequest, "principal_id, app_slug, resource_type, and action are required")
		return
	}
	if req.Context.ClientIP == "" {
		req.Context.ClientIP = extractClientIP(r)
	}

	resp, err := s.pdp.Authorize(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authorization evaluation failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBatchAuthorize(w http.ResponseWriter, r *http.Request) {
	var req domain.BatchAuthorizeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.PrincipalID == uuid.Nil || req.AppSlug == "" || len(req.Checks) == 0 {
		writeError(w, http.StatusBadRequest, "principal_id, app_slug, and non-empty checks array are required")
		return
	}
	if len(req.Checks) > 100 {
		writeError(w, http.StatusBadRequest, "maximum 100 checks allowed per batch request")
		return
	}
	if req.Context.ClientIP == "" {
		req.Context.ClientIP = extractClientIP(r)
	}

	resp, err := s.pdp.BatchAuthorize(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "batch authorization evaluation failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ============================================================================
// Admin Registration Handlers (IdPs, Orgs, Apps, Permissions, Roles, Grants)
// ============================================================================

func (s *Server) handleListIdPs(w http.ResponseWriter, r *http.Request) {
	idps, err := s.store.ListIdentityProviders(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"identity_providers": idps})
}

func (s *Server) handleCreateIdP(w http.ResponseWriter, r *http.Request) {
	var idp domain.IdentityProvider
	if err := decodeJSON(r, &idp); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if idp.Slug == "" || idp.Name == "" || idp.IssuerURL == "" || idp.ClientID == "" {
		writeError(w, http.StatusBadRequest, "slug, name, issuer_url, and client_id are required")
		return
	}
	if idp.ProviderType == "" {
		idp.ProviderType = domain.IdPGenericOIDC
	}
	created, err := s.store.CreateIdentityProvider(r.Context(), idp)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleListOrganizations(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.store.ListOrganizations(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"organizations": orgs})
}

func (s *Server) handleCreateOrganization(w http.ResponseWriter, r *http.Request) {
	var org domain.Organization
	if err := decodeJSON(r, &org); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if org.Slug == "" || org.Name == "" || org.OrgType == "" || org.HierarchyPath == "" {
		writeError(w, http.StatusBadRequest, "slug, name, org_type, and hierarchy_path (ltree) are required")
		return
	}
	created, err := s.store.CreateOrganization(r.Context(), org)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var grp domain.Group
	if err := decodeJSON(r, &grp); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if grp.Slug == "" || grp.Name == "" {
		writeError(w, http.StatusBadRequest, "slug and name are required")
		return
	}
	created, err := s.store.CreateGroup(r.Context(), grp)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleAddGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID, err := uuid.Parse(r.PathValue("groupID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid groupID UUID")
		return
	}
	var body struct {
		UserID    uuid.UUID  `json:"user_id"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil || body.UserID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "valid user_id is required")
		return
	}
	if err := s.store.AddUserToGroup(r.Context(), groupID, body.UserID, body.ExpiresAt); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "member_added", "group_id": groupID, "user_id": body.UserID})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context(), 100, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApplications(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"applications": apps})
}

func (s *Server) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	var app domain.Application
	if err := decodeJSON(r, &app); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if app.Slug == "" || app.Name == "" {
		writeError(w, http.StatusBadRequest, "slug and name are required")
		return
	}
	created, err := s.store.CreateApplication(r.Context(), app)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleBindAppIdP(w http.ResponseWriter, r *http.Request) {
	app, err := s.store.GetApplicationBySlug(r.Context(), r.PathValue("appSlug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "application not found")
		return
	}
	var body struct {
		IdPSlug        string     `json:"idp_slug"`
		IdPID          *uuid.UUID `json:"idp_id,omitempty"`
		AllowJITSignup bool       `json:"allow_jit_signup"`
		DefaultRoleID  *uuid.UUID `json:"default_role_id,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var idpID uuid.UUID
	if body.IdPID != nil {
		idpID = *body.IdPID
	} else if body.IdPSlug != "" {
		idp, err := s.store.GetIdentityProviderBySlug(r.Context(), body.IdPSlug)
		if err != nil {
			writeError(w, http.StatusNotFound, "identity provider not found")
			return
		}
		idpID = idp.ID
	} else {
		writeError(w, http.StatusBadRequest, "idp_slug or idp_id is required")
		return
	}

	binding := domain.AppIdentityProvider{
		ApplicationID:  app.ID,
		IdPID:          idpID,
		AllowJITSignup: body.AllowJITSignup,
		DefaultRoleID:  body.DefaultRoleID,
	}
	if err := s.store.BindAppIdentityProvider(r.Context(), binding); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, binding)
}

func (s *Server) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	app, err := s.store.GetApplicationBySlug(r.Context(), r.PathValue("appSlug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "application not found")
		return
	}
	perms, err := s.store.ListPermissionsByApp(r.Context(), app.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": perms})
}

func (s *Server) handleCreatePermission(w http.ResponseWriter, r *http.Request) {
	app, err := s.store.GetApplicationBySlug(r.Context(), r.PathValue("appSlug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "application not found")
		return
	}
	var perm domain.Permission
	if err := decodeJSON(r, &perm); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if perm.ResourceType == "" || perm.Action == "" {
		writeError(w, http.StatusBadRequest, "resource_type and action are required")
		return
	}
	perm.ApplicationID = app.ID
	created, err := s.store.CreatePermission(r.Context(), perm)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	app, err := s.store.GetApplicationBySlug(r.Context(), r.PathValue("appSlug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "application not found")
		return
	}
	roles, err := s.store.ListRolesByApp(r.Context(), app.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	app, err := s.store.GetApplicationBySlug(r.Context(), r.PathValue("appSlug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "application not found")
		return
	}
	var body struct {
		Slug          string      `json:"slug"`
		Name          string      `json:"name"`
		Description   string      `json:"description"`
		IsSystemRole  bool        `json:"is_system_role"`
		InheritsFrom  *uuid.UUID  `json:"inherits_from,omitempty"`
		PermissionIDs []uuid.UUID `json:"permission_ids,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Slug == "" || body.Name == "" {
		writeError(w, http.StatusBadRequest, "slug and name are required")
		return
	}

	role, err := s.store.CreateRole(r.Context(), domain.Role{
		ApplicationID: app.ID,
		Slug:          body.Slug,
		Name:          body.Name,
		Description:   body.Description,
		IsSystemRole:  body.IsSystemRole,
		InheritsFrom:  body.InheritsFrom,
	})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	for _, permID := range body.PermissionIDs {
		_ = s.store.AttachPermissionToRole(r.Context(), role.ID, permID, domain.ABACConditions{})
	}
	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) handleAttachPermissionToRole(w http.ResponseWriter, r *http.Request) {
	app, err := s.store.GetApplicationBySlug(r.Context(), r.PathValue("appSlug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "application not found")
		return
	}
	role, err := s.store.GetRoleBySlug(r.Context(), app.ID, r.PathValue("roleSlug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "role not found")
		return
	}
	var body struct {
		PermissionID uuid.UUID             `json:"permission_id"`
		Conditions   domain.ABACConditions `json:"conditions"`
	}
	if err := decodeJSON(r, &body); err != nil || body.PermissionID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "valid permission_id is required")
		return
	}
	if err := s.store.AttachPermissionToRole(r.Context(), role.ID, body.PermissionID, body.Conditions); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "permission_attached",
		"role_id":       role.ID,
		"permission_id": body.PermissionID,
	})
}

func (s *Server) handleListAssignments(w http.ResponseWriter, r *http.Request) {
	app, err := s.store.GetApplicationBySlug(r.Context(), r.PathValue("appSlug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "application not found")
		return
	}
	list, err := s.store.ListRoleAssignmentsByApp(r.Context(), app.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assignments": list})
}

func (s *Server) handleCreateAssignment(w http.ResponseWriter, r *http.Request) {
	app, err := s.store.GetApplicationBySlug(r.Context(), r.PathValue("appSlug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "application not found")
		return
	}
	var req struct {
		RoleID           *uuid.UUID            `json:"role_id,omitempty"`
		RoleSlug         string                `json:"role_slug,omitempty"`
		PrincipalType    domain.PrincipalType  `json:"principal_type"`
		UserID           *uuid.UUID            `json:"user_id,omitempty"`
		GroupID          *uuid.UUID            `json:"group_id,omitempty"`
		Effect           domain.GrantEffect    `json:"effect"`
		OrganizationID   *uuid.UUID            `json:"organization_id,omitempty"`
		IncludeChildOrgs *bool                 `json:"include_child_orgs,omitempty"`
		ResourceType     *string               `json:"resource_type,omitempty"`
		ResourceID       *string               `json:"resource_id,omitempty"`
		Conditions       domain.ABACConditions `json:"conditions"`
		Justification    string                `json:"justification"`
		StartsAt         *time.Time            `json:"starts_at,omitempty"`
		ExpiresAt        *time.Time            `json:"expires_at,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var roleID uuid.UUID
	if req.RoleID != nil {
		roleID = *req.RoleID
	} else if req.RoleSlug != "" {
		role, err := s.store.GetRoleBySlug(r.Context(), app.ID, req.RoleSlug)
		if err != nil {
			writeError(w, http.StatusNotFound, "role not found in application")
			return
		}
		roleID = role.ID
	} else {
		writeError(w, http.StatusBadRequest, "role_id or role_slug is required")
		return
	}

	includeChildren := true
	if req.IncludeChildOrgs != nil {
		includeChildren = *req.IncludeChildOrgs
	}
	startsAt := time.Now().UTC()
	if req.StartsAt != nil {
		startsAt = *req.StartsAt
	}

	ra := domain.RoleAssignment{
		ApplicationID:    app.ID,
		RoleID:           roleID,
		PrincipalType:    req.PrincipalType,
		UserID:           req.UserID,
		GroupID:          req.GroupID,
		Effect:           req.Effect,
		OrganizationID:   req.OrganizationID,
		IncludeChildOrgs: includeChildren,
		ResourceType:     req.ResourceType,
		ResourceID:       req.ResourceID,
		Conditions:       req.Conditions,
		Justification:    req.Justification,
		StartsAt:         startsAt,
		ExpiresAt:        req.ExpiresAt,
	}

	created, err := s.store.CreateRoleAssignment(r.Context(), ra)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleDeleteAssignment(w http.ResponseWriter, r *http.Request) {
	app, err := s.store.GetApplicationBySlug(r.Context(), r.PathValue("appSlug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "application not found")
		return
	}
	assignmentID, err := uuid.Parse(r.PathValue("assignmentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid assignmentID UUID")
		return
	}
	if err := s.store.DeleteRoleAssignment(r.Context(), app.ID, assignmentID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "assignment not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Zero Trust Admin Protection Middleware & Helpers
// ============================================================================

func (s *Server) requireAdmin(resourceType, action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Allow bootstrap API key if explicitly configured on the server
		if s.adminBootstrapKey != "" {
			if providedKey := r.Header.Get("X-Admin-Bootstrap-Key"); providedKey != "" && providedKey == s.adminBootstrapKey {
				next(w, r)
				return
			}
		}

		// 2. Otherwise require a valid Bearer JWT scoped to 'utah-iam-admin' AND verify via Zero Trust PDP
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing Bearer token or X-Admin-Bootstrap-Key")
			return
		}
		rawToken := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := s.tokenSvc.VerifyAppToken(rawToken, AdminAppSlug)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid admin token: "+err.Error())
			return
		}

		principalID, err := uuid.Parse(claims.Subject)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token subject UUID")
			return
		}

		decision, err := s.pdp.Authorize(r.Context(), domain.AuthorizeRequest{
			PrincipalID:    principalID,
			AppSlug:        AdminAppSlug,
			ResourceType:   resourceType,
			Action:         action,
			OrganizationID: claims.OrganizationID,
			Context: domain.RequestContext{
				ClientIP:    extractClientIP(r),
				MFAVerified: claims.MFAVerified,
				UserType:    claims.UserType,
			},
		})
		if err != nil || !decision.Allowed {
			reason := "access_denied"
			if decision != nil {
				reason = decision.Reason
			}
			writeError(w, http.StatusForbidden, "zero trust admin policy denied request: "+reason)
			return
		}

		next(w, r)
	}
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader( nil, r.Body, 1<<20)) // 1 MB limit
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error":  http.StatusText(status),
		"detail": message,
	})
}

func extractClientIP(r *http.Request) string {
	// Respect GCP Cloud Run / Load Balancer X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
