package db

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
)

// MemoryStore is a thread-safe in-memory implementation of Store for unit and integration testing.
type MemoryStore struct {
	mu              sync.RWMutex
	idps            map[uuid.UUID]domain.IdentityProvider
	users           map[uuid.UUID]domain.User
	identities      map[string]uuid.UUID // key: idpID.String() + "|" + subject -> userID
	orgs            map[uuid.UUID]domain.Organization
	groups          map[uuid.UUID]domain.Group
	groupMembers    map[uuid.UUID][]uuid.UUID // groupID -> []userID
	apps            map[uuid.UUID]domain.Application
	appIdPs         map[string]domain.AppIdentityProvider // appID|idpID
	permissions     map[uuid.UUID]domain.Permission
	roles           map[uuid.UUID]domain.Role
	rolePerms       map[uuid.UUID]map[uuid.UUID]domain.ABACConditions // roleID -> permID -> cond
	assignments     map[uuid.UUID]domain.RoleAssignment
	auditLogs       []domain.AuditLog
}

// NewMemoryStore creates an initialized in-memory Store for testing.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		idps:         make(map[uuid.UUID]domain.IdentityProvider),
		users:        make(map[uuid.UUID]domain.User),
		identities:   make(map[string]uuid.UUID),
		orgs:         make(map[uuid.UUID]domain.Organization),
		groups:       make(map[uuid.UUID]domain.Group),
		groupMembers: make(map[uuid.UUID][]uuid.UUID),
		apps:         make(map[uuid.UUID]domain.Application),
		appIdPs:      make(map[string]domain.AppIdentityProvider),
		permissions:  make(map[uuid.UUID]domain.Permission),
		roles:        make(map[uuid.UUID]domain.Role),
		rolePerms:    make(map[uuid.UUID]map[uuid.UUID]domain.ABACConditions),
		assignments:  make(map[uuid.UUID]domain.RoleAssignment),
	}
}

func (m *MemoryStore) CreateIdentityProvider(_ context.Context, idp domain.IdentityProvider) (*domain.IdentityProvider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idp.ID == uuid.Nil {
		idp.ID = uuid.New()
	}
	now := time.Now().UTC()
	idp.CreatedAt = now
	idp.UpdatedAt = now
	m.idps[idp.ID] = idp
	return &idp, nil
}

func (m *MemoryStore) GetIdentityProviderByIssuer(_ context.Context, issuerURL string) (*domain.IdentityProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, idp := range m.idps {
		if idp.IssuerURL == issuerURL && idp.IsActive {
			cp := idp
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) GetIdentityProviderBySlug(_ context.Context, slug string) (*domain.IdentityProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, idp := range m.idps {
		if idp.Slug == slug {
			cp := idp
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) ListIdentityProviders(_ context.Context) ([]domain.IdentityProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.IdentityProvider, 0, len(m.idps))
	for _, idp := range m.idps {
		out = append(out, idp)
	}
	return out, nil
}

func (m *MemoryStore) ResolveOrProvisionUser(
	_ context.Context,
	idp *domain.IdentityProvider,
	subject, email, displayName string,
	emailVerified bool,
	_ map[string]any,
	externalGroups []string,
) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := idp.ID.String() + "|" + subject
	if uid, ok := m.identities[key]; ok {
		u := m.users[uid]
		return &u, nil
	}

	if !idp.AutoProvision {
		return nil, ErrUnauthorized
	}

	userType := "external_partner"
	if idp.IsInternalState {
		userType = "state_employee"
	}
	now := time.Now().UTC()
	u := domain.User{
		ID:            uuid.New(),
		Email:         strings.ToLower(email),
		EmailVerified: emailVerified,
		DisplayName:   displayName,
		UserType:      userType,
		Status:        domain.UserStatusActive,
		Attributes:    map[string]any{},
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	m.users[u.ID] = u
	m.identities[key] = u.ID

	// Sync external groups
	for _, g := range m.groups {
		if g.ExternalIdPID != nil && *g.ExternalIdPID == idp.ID && slices.Contains(externalGroups, g.ExternalGroupID) {
			if !slices.Contains(m.groupMembers[g.ID], u.ID) {
				m.groupMembers[g.ID] = append(m.groupMembers[g.ID], u.ID)
			}
		}
	}

	return &u, nil
}

func (m *MemoryStore) GetUserByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &u, nil
}

func (m *MemoryStore) ListUsers(_ context.Context, _, _ int) ([]domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	return out, nil
}

func (m *MemoryStore) CreateOrganization(_ context.Context, org domain.Organization) (*domain.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if org.ID == uuid.Nil {
		org.ID = uuid.New()
	}
	now := time.Now().UTC()
	org.CreatedAt = now
	org.UpdatedAt = now
	m.orgs[org.ID] = org
	return &org, nil
}

func (m *MemoryStore) ListOrganizations(_ context.Context) ([]domain.Organization, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Organization, 0, len(m.orgs))
	for _, o := range m.orgs {
		out = append(out, o)
	}
	return out, nil
}

func (m *MemoryStore) CreateGroup(_ context.Context, grp domain.Group) (*domain.Group, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if grp.ID == uuid.Nil {
		grp.ID = uuid.New()
	}
	grp.CreatedAt = time.Now().UTC()
	m.groups[grp.ID] = grp
	return &grp, nil
}

func (m *MemoryStore) AddUserToGroup(_ context.Context, groupID, userID uuid.UUID, _ *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !slices.Contains(m.groupMembers[groupID], userID) {
		m.groupMembers[groupID] = append(m.groupMembers[groupID], userID)
	}
	return nil
}

func (m *MemoryStore) CreateApplication(_ context.Context, app domain.Application) (*domain.Application, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if app.ID == uuid.Nil {
		app.ID = uuid.New()
	}
	if app.TokenTTLSeconds <= 0 {
		app.TokenTTLSeconds = 900
	}
	now := time.Now().UTC()
	app.CreatedAt = now
	app.UpdatedAt = now
	m.apps[app.ID] = app
	return &app, nil
}

func (m *MemoryStore) GetApplicationBySlug(_ context.Context, slug string) (*domain.Application, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, app := range m.apps {
		if app.Slug == slug {
			cp := app
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) ListApplications(_ context.Context) ([]domain.Application, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Application, 0, len(m.apps))
	for _, app := range m.apps {
		out = append(out, app)
	}
	return out, nil
}

func (m *MemoryStore) BindAppIdentityProvider(_ context.Context, b domain.AppIdentityProvider) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appIdPs[b.ApplicationID.String()+"|"+b.IdPID.String()] = b
	return nil
}

func (m *MemoryStore) GetAppIdentityProvider(_ context.Context, appID, idpID uuid.UUID) (*domain.AppIdentityProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.appIdPs[appID.String()+"|"+idpID.String()]
	if !ok {
		return nil, ErrNotFound
	}
	return &b, nil
}

func (m *MemoryStore) CreatePermission(_ context.Context, perm domain.Permission) (*domain.Permission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if perm.ID == uuid.Nil {
		perm.ID = uuid.New()
	}
	perm.Slug = perm.ResourceType + ":" + perm.Action
	perm.CreatedAt = time.Now().UTC()
	m.permissions[perm.ID] = perm
	return &perm, nil
}

func (m *MemoryStore) ListPermissionsByApp(_ context.Context, appID uuid.UUID) ([]domain.Permission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []domain.Permission
	for _, p := range m.permissions {
		if p.ApplicationID == appID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (m *MemoryStore) CreateRole(_ context.Context, role domain.Role) (*domain.Role, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	now := time.Now().UTC()
	role.CreatedAt = now
	role.UpdatedAt = now
	m.roles[role.ID] = role
	return &role, nil
}

func (m *MemoryStore) GetRoleBySlug(_ context.Context, appID uuid.UUID, slug string) (*domain.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.roles {
		if r.ApplicationID == appID && r.Slug == slug {
			cp := r
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) ListRolesByApp(_ context.Context, appID uuid.UUID) ([]domain.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []domain.Role
	for _, r := range m.roles {
		if r.ApplicationID == appID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *MemoryStore) AttachPermissionToRole(_ context.Context, roleID, permissionID uuid.UUID, conditions domain.ABACConditions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rolePerms[roleID] == nil {
		m.rolePerms[roleID] = make(map[uuid.UUID]domain.ABACConditions)
	}
	m.rolePerms[roleID][permissionID] = conditions
	return nil
}

func (m *MemoryStore) CreateRoleAssignment(_ context.Context, ra domain.RoleAssignment) (*domain.RoleAssignment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ra.ID == uuid.Nil {
		ra.ID = uuid.New()
	}
	if ra.Effect == "" {
		ra.Effect = domain.EffectAllow
	}
	if ra.StartsAt.IsZero() {
		ra.StartsAt = time.Now().UTC().Add(-time.Second)
	}
	ra.CreatedAt = time.Now().UTC()
	m.assignments[ra.ID] = ra
	return &ra, nil
}

func (m *MemoryStore) DeleteRoleAssignment(_ context.Context, appID, assignmentID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ra, ok := m.assignments[assignmentID]
	if !ok || ra.ApplicationID != appID {
		return ErrNotFound
	}
	delete(m.assignments, assignmentID)
	return nil
}

func (m *MemoryStore) ListRoleAssignmentsByApp(_ context.Context, appID uuid.UUID) ([]domain.RoleAssignment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []domain.RoleAssignment
	for _, ra := range m.assignments {
		if ra.ApplicationID == appID {
			out = append(out, ra)
		}
	}
	return out, nil
}

func (m *MemoryStore) ListUserActiveRolesForApp(_ context.Context, userID, appID uuid.UUID, orgID *uuid.UUID) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now().UTC()
	var roles []string
	for _, ra := range m.assignments {
		if ra.ApplicationID != appID || ra.Effect != domain.EffectAllow || ra.ResourceID != nil {
			continue
		}
		if ra.StartsAt.After(now) || (ra.ExpiresAt != nil && ra.ExpiresAt.Before(now)) {
			continue
		}
		if !m.principalMatchesLocked(ra, userID) {
			continue
		}
		if ra.OrganizationID != nil && (orgID == nil || *ra.OrganizationID != *orgID) {
			continue
		}
		if r, ok := m.roles[ra.RoleID]; ok && !slices.Contains(roles, r.Slug) {
			roles = append(roles, r.Slug)
		}
	}
	return roles, nil
}

func (m *MemoryStore) FindMatchingGrants(_ context.Context, req domain.AuthorizeRequest) ([]domain.MatchedGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var app *domain.Application
	for _, a := range m.apps {
		if a.Slug == req.AppSlug && a.IsActive {
			cp := a
			app = &cp
			break
		}
	}
	if app == nil {
		return nil, nil
	}

	now := time.Now().UTC()
	var out []domain.MatchedGrant

	for _, ra := range m.assignments {
		if ra.ApplicationID != app.ID {
			continue
		}
		if ra.StartsAt.After(now) || (ra.ExpiresAt != nil && ra.ExpiresAt.Before(now)) {
			continue
		}
		if !m.principalMatchesLocked(ra, req.PrincipalID) {
			continue
		}
		if !m.orgMatchesLocked(ra, req.OrganizationID) {
			continue
		}
		if ra.ResourceID != nil {
			if ra.ResourceType == nil || *ra.ResourceType != req.ResourceType || *ra.ResourceID != req.ResourceID {
				continue
			}
		}

		// Traverse role and any inherited parent roles
		rootRole, ok := m.roles[ra.RoleID]
		if !ok {
			continue
		}
		curRole := &rootRole
		for curRole != nil {
			for permID, permCond := range m.rolePerms[curRole.ID] {
				perm, ok := m.permissions[permID]
				if !ok {
					continue
				}
				if (perm.ResourceType == req.ResourceType || perm.ResourceType == "*") &&
					(perm.Action == req.Action || perm.Action == "*") {
					out = append(out, domain.MatchedGrant{
						AssignmentID:         ra.ID,
						Effect:               ra.Effect,
						RoleSlug:             rootRole.Slug,
						PermissionSlug:       perm.Slug,
						OrganizationID:       ra.OrganizationID,
						ResourceType:         ra.ResourceType,
						ResourceID:           ra.ResourceID,
						AssignmentConditions: ra.Conditions,
						PermissionConditions: permCond,
					})
				}
			}
			if curRole.InheritsFrom != nil {
				parent, ok := m.roles[*curRole.InheritsFrom]
				if ok {
					curRole = &parent
				} else {
					curRole = nil
				}
			} else {
				curRole = nil
			}
		}
	}
	return out, nil
}

func (m *MemoryStore) InsertAuditLog(_ context.Context, entry domain.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry.ID = uuid.New()
	entry.EventTime = time.Now().UTC()
	m.auditLogs = append(m.auditLogs, entry)
	return nil
}

func (m *MemoryStore) principalMatchesLocked(ra domain.RoleAssignment, userID uuid.UUID) bool {
	if ra.PrincipalType == domain.PrincipalUser && ra.UserID != nil && *ra.UserID == userID {
		return true
	}
	if ra.PrincipalType == domain.PrincipalGroup && ra.GroupID != nil {
		return slices.Contains(m.groupMembers[*ra.GroupID], userID)
	}
	return false
}

func (m *MemoryStore) orgMatchesLocked(ra domain.RoleAssignment, reqOrgID *uuid.UUID) bool {
	if ra.OrganizationID == nil {
		return true
	}
	if reqOrgID == nil {
		return false
	}
	if *ra.OrganizationID == *reqOrgID {
		return true
	}
	if !ra.IncludeChildOrgs {
		return false
	}
	assignedOrg, ok1 := m.orgs[*ra.OrganizationID]
	reqOrg, ok2 := m.orgs[*reqOrgID]
	if !ok1 || !ok2 || !assignedOrg.IsActive || !reqOrg.IsActive {
		return false
	}
	// Emulate PostgreSQL ltree '<@' descendant check
	return strings.HasPrefix(reqOrg.HierarchyPath, assignedOrg.HierarchyPath+".")
}
