package domain

import (
	"time"

	"github.com/google/uuid"
)

// IdPType enumerates supported upstream OIDC identity provider categories.
type IdPType string

const (
	IdPUtahID              IdPType = "utahid"
	IdPGCPIdentityPlatform IdPType = "gcp_identity_platform"
	IdPGoogleIAP           IdPType = "google_iap"
	IdPEntraID             IdPType = "entra_id"
	IdPGoogle              IdPType = "google"
	IdPGenericOIDC         IdPType = "generic_oidc"

	// IAPIssuerURL is the fixed 'iss' claim of Google Cloud Identity-Aware Proxy JWT assertions.
	IAPIssuerURL = "https://cloud.google.com/iap"
	// IAPJWKSURI publishes Google IAP's ES256 public keys in standard JWKS format.
	IAPJWKSURI = "https://www.gstatic.com/iap/verify/public_key-jwk"
)

// ClaimMappings defines how upstream OIDC claims map to canonical Utah AuthZ user attributes.
type ClaimMappings struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Groups  string `json:"groups"`
	MFA     string `json:"mfa"`
	Agency  string `json:"agency,omitempty"`
}

// IdentityProvider represents a trusted OIDC issuer (e.g., UtahID or an external partner IdP).
type IdentityProvider struct {
	ID              uuid.UUID     `json:"id"`
	Slug            string        `json:"slug"`
	Name            string        `json:"name"`
	ProviderType    IdPType       `json:"provider_type"`
	IssuerURL       string        `json:"issuer_url"`
	ClientID        string        `json:"client_id"`
	JWKSURI         string        `json:"jwks_uri,omitempty"`
	ClaimMappings   ClaimMappings `json:"claim_mappings"`
	IsInternalState bool          `json:"is_internal_state"`
	AutoProvision   bool          `json:"auto_provision"`
	IsActive        bool          `json:"is_active"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

// UserStatus represents the lifecycle state of a canonical user.
type UserStatus string

const (
	UserStatusActive              UserStatus = "active"
	UserStatusSuspended           UserStatus = "suspended"
	UserStatusPendingVerification UserStatus = "pending_verification"
	UserStatusDeactivated         UserStatus = "deactivated"
)

// User represents a canonical person or service account across UtahID and external IdPs.
type User struct {
	ID            uuid.UUID      `json:"id"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	DisplayName   string         `json:"display_name"`
	UserType      string         `json:"user_type"` // 'state_employee', 'external_partner', 'public', 'service_account'
	Status        UserStatus     `json:"status"`
	Attributes    map[string]any `json:"attributes"`
	LastLoginAt   *time.Time     `json:"last_login_at,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// UserIdentity links an upstream OIDC subject (e.g. UtahID sub) to a canonical User.
type UserIdentity struct {
	ID                uuid.UUID      `json:"id"`
	UserID            uuid.UUID      `json:"user_id"`
	IdPID             uuid.UUID      `json:"idp_id"`
	IdPSubject        string         `json:"idp_subject"`
	IdPEmail          string         `json:"idp_email"`
	RawClaims         map[string]any `json:"raw_claims"`
	LastAuthenticated time.Time      `json:"last_authenticated"`
	CreatedAt         time.Time      `json:"created_at"`
}

// Organization represents a hierarchical tenant (State Agency, Division, Water District, Consultant).
type Organization struct {
	ID            uuid.UUID      `json:"id"`
	Slug          string         `json:"slug"`
	Name          string         `json:"name"`
	OrgType       string         `json:"org_type"`
	ParentID      *uuid.UUID     `json:"parent_id,omitempty"`
	HierarchyPath string         `json:"hierarchy_path"` // ltree path, e.g. 'state_of_utah.dnr.dwre'
	IsActive      bool           `json:"is_active"`
	Metadata      map[string]any `json:"metadata"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// Group represents a collection of users, optionally mapped from an external OIDC group claim.
type Group struct {
	ID              uuid.UUID  `json:"id"`
	OrganizationID  *uuid.UUID `json:"organization_id,omitempty"`
	Slug            string     `json:"slug"`
	Name            string     `json:"name"`
	Description     string     `json:"description,omitempty"`
	ExternalIdPID   *uuid.UUID `json:"external_idp_id,omitempty"`
	ExternalGroupID string     `json:"external_group_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// Application represents a registered downstream application (e.g. 'water-resources-map').
type Application struct {
	ID              uuid.UUID      `json:"id"`
	Slug            string         `json:"slug"`
	Name            string         `json:"name"`
	Description     string         `json:"description,omitempty"`
	OwnerOrgID      *uuid.UUID     `json:"owner_org_id,omitempty"`
	AllowedOrigins  []string       `json:"allowed_origins"`
	TokenTTLSeconds int            `json:"token_ttl_seconds"`
	RequireMFA      bool           `json:"require_mfa"`
	IsActive        bool           `json:"is_active"`
	Metadata        map[string]any `json:"metadata"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// AppIdentityProvider binds a trusted IdentityProvider to an Application.
type AppIdentityProvider struct {
	ApplicationID  uuid.UUID  `json:"application_id"`
	IdPID          uuid.UUID  `json:"idp_id"`
	AllowJITSignup bool       `json:"allow_jit_signup"`
	DefaultRoleID  *uuid.UUID `json:"default_role_id,omitempty"`
}

// Permission represents an atomic (resource_type, action) capability defined within an Application.
type Permission struct {
	ID            uuid.UUID `json:"id"`
	ApplicationID uuid.UUID `json:"application_id"`
	ResourceType  string    `json:"resource_type"`
	Action        string    `json:"action"`
	Slug          string    `json:"slug"` // Generated as resource_type:action
	Description   string    `json:"description,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// Role bundles permissions within an Application.
type Role struct {
	ID            uuid.UUID  `json:"id"`
	ApplicationID uuid.UUID  `json:"application_id"`
	Slug          string     `json:"slug"`
	Name          string     `json:"name"`
	Description   string     `json:"description,omitempty"`
	IsSystemRole  bool       `json:"is_system_role"`
	InheritsFrom  *uuid.UUID `json:"inherits_from,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// ABACConditions defines Zero Trust contextual conditions evaluated at authorization time.
type ABACConditions struct {
	RequireMFA         bool              `json:"require_mfa,omitempty"`
	IPCIDRs            []string          `json:"ip_cidrs,omitempty"`
	AllowedUserTypes   []string          `json:"allowed_user_types,omitempty"`
	RequiredAttributes map[string]string `json:"required_attributes,omitempty"`
	AllowedHoursUTC    *TimeWindowUTC    `json:"allowed_hours_utc,omitempty"`
}

// TimeWindowUTC restricts access to specific UTC hours of the day (0-23).
type TimeWindowUTC struct {
	StartHour int `json:"start_hour"`
	EndHour   int `json:"end_hour"`
}

// GrantEffect is either 'allow' or 'deny'. Explicit 'deny' always overrides 'allow'.
type GrantEffect string

const (
	EffectAllow GrantEffect = "allow"
	EffectDeny  GrantEffect = "deny"
)

// PrincipalType indicates whether a role assignment targets a User or a Group.
type PrincipalType string

const (
	PrincipalUser  PrincipalType = "user"
	PrincipalGroup PrincipalType = "group"
)

// RoleAssignment grants or denies a Role to a User or Group at Global, Org, or Resource scope.
type RoleAssignment struct {
	ID               uuid.UUID      `json:"id"`
	ApplicationID    uuid.UUID      `json:"application_id"`
	RoleID           uuid.UUID      `json:"role_id"`
	PrincipalType    PrincipalType  `json:"principal_type"`
	UserID           *uuid.UUID     `json:"user_id,omitempty"`
	GroupID          *uuid.UUID     `json:"group_id,omitempty"`
	Effect           GrantEffect    `json:"effect"`
	OrganizationID   *uuid.UUID     `json:"organization_id,omitempty"`
	IncludeChildOrgs bool           `json:"include_child_orgs"`
	ResourceType     *string        `json:"resource_type,omitempty"`
	ResourceID       *string        `json:"resource_id,omitempty"`
	Conditions       ABACConditions `json:"conditions"`
	GrantedBy        *uuid.UUID     `json:"granted_by,omitempty"`
	Justification    string         `json:"justification,omitempty"`
	StartsAt         time.Time      `json:"starts_at"`
	ExpiresAt        *time.Time     `json:"expires_at,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
}

// MatchedGrant represents a candidate grant row returned from PostgreSQL during PDP evaluation.
type MatchedGrant struct {
	AssignmentID         uuid.UUID      `json:"assignment_id"`
	Effect               GrantEffect    `json:"effect"`
	RoleSlug             string         `json:"role_slug"`
	PermissionSlug       string         `json:"permission_slug"`
	OrganizationID       *uuid.UUID     `json:"organization_id,omitempty"`
	ResourceType         *string        `json:"resource_type,omitempty"`
	ResourceID           *string        `json:"resource_id,omitempty"`
	AssignmentConditions ABACConditions `json:"assignment_conditions"`
	PermissionConditions ABACConditions `json:"permission_conditions"`
}

// RequestContext holds runtime environmental attributes for Zero Trust ABAC evaluation.
type RequestContext struct {
	ClientIP      string            `json:"client_ip,omitempty"`
	MFAVerified   bool              `json:"mfa_verified"`
	UserType      string            `json:"user_type,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	EvaluationUTC *time.Time        `json:"-"` // Optional override for deterministic testing
}

// AuthorizeRequest represents a real-time Policy Decision Point (PDP) check.
type AuthorizeRequest struct {
	PrincipalID    uuid.UUID      `json:"principal_id"`
	AppSlug        string         `json:"app_slug"`
	ResourceType   string         `json:"resource_type"`
	ResourceID     string         `json:"resource_id,omitempty"`
	Action         string         `json:"action"`
	OrganizationID *uuid.UUID     `json:"organization_id,omitempty"`
	Context        RequestContext `json:"context"`
}

// AuthorizeResponse is the Zero Trust decision returned by /v1/authorize.
type AuthorizeResponse struct {
	Allowed       bool       `json:"allowed"`
	Decision      string     `json:"decision"` // "allow" or "deny"
	Reason        string     `json:"reason"`
	MatchedRole   string     `json:"matched_role,omitempty"`
	AssignmentID  *uuid.UUID `json:"assignment_id,omitempty"`
	EvaluatedAt   time.Time  `json:"evaluated_at"`
}

// BatchAuthorizeItem represents a single check inside a batch request.
type BatchAuthorizeItem struct {
	CheckID        string     `json:"check_id"`
	ResourceType   string     `json:"resource_type"`
	ResourceID     string     `json:"resource_id,omitempty"`
	Action         string     `json:"action"`
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`
}

// BatchAuthorizeRequest allows UIs or map servers to check many layers/actions in a single round-trip.
type BatchAuthorizeRequest struct {
	PrincipalID uuid.UUID            `json:"principal_id"`
	AppSlug     string               `json:"app_slug"`
	Context     RequestContext       `json:"context"`
	Checks      []BatchAuthorizeItem `json:"checks"`
}

// BatchAuthorizeResponse maps each check_id to its AuthorizeResponse.
type BatchAuthorizeResponse struct {
	Results map[string]AuthorizeResponse `json:"results"`
}

// AuditLog represents an immutable security or administrative event record.
type AuditLog struct {
	ID            uuid.UUID      `json:"id"`
	EventTime     time.Time      `json:"event_time"`
	ActorUserID   *uuid.UUID     `json:"actor_user_id,omitempty"`
	ActorIP       string         `json:"actor_ip,omitempty"`
	ApplicationID *uuid.UUID     `json:"application_id,omitempty"`
	EventType     string         `json:"event_type"`
	TargetType    string         `json:"target_type,omitempty"`
	TargetID      string         `json:"target_id,omitempty"`
	Decision      string         `json:"decision,omitempty"`
	Payload       map[string]any `json:"payload"`
}
