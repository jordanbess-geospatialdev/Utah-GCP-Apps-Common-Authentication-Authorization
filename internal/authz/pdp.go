package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/db"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
)

// PDP is the Zero Trust Policy Decision Point engine.
type PDP struct {
	store db.Store
}

// NewPDP creates a new Policy Decision Point backed by the given Store.
func NewPDP(store db.Store) *PDP {
	return &PDP{store: store}
}

// Authorize evaluates a single Zero Trust authorization request with deterministic precedence:
// 1. Verify Principal is active & enrich user attributes
// 2. Verify Application is active & enforce app-level MFA policy
// 3. Query all matching role/permission grants (Global, Org ltree, or Resource-Instance scope)
// 4. Explicit DENY overrides all ALLOW grants
// 5. Evaluate ABAC conditions on candidate ALLOW grants
// 6. Default DENY if no valid grant matches
func (p *PDP) Authorize(ctx context.Context, req domain.AuthorizeRequest) (*domain.AuthorizeResponse, error) {
	now := time.Now().UTC()

	// 1. Verify Principal exists and is active
	user, err := p.store.GetUserByID(ctx, req.PrincipalID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return p.recordAndReturn(ctx, req, nil, &domain.AuthorizeResponse{
				Allowed:     false,
				Decision:    string(domain.EffectDeny),
				Reason:      "principal_not_found",
				EvaluatedAt: now,
			}), nil
		}
		return nil, fmt.Errorf("fetch principal: %w", err)
	}

	if user.Status != domain.UserStatusActive {
		return p.recordAndReturn(ctx, req, nil, &domain.AuthorizeResponse{
			Allowed:     false,
			Decision:    string(domain.EffectDeny),
			Reason:      fmt.Sprintf("principal_status_%s", user.Status),
			EvaluatedAt: now,
		}), nil
	}

	// Enrich RequestContext with canonical user attributes if not provided by caller
	if req.Context.UserType == "" {
		req.Context.UserType = user.UserType
	}
	if req.Context.Attributes == nil {
		req.Context.Attributes = make(map[string]string)
	}
	for k, v := range user.Attributes {
		if strVal, ok := v.(string); ok {
			if _, exists := req.Context.Attributes[k]; !exists {
				req.Context.Attributes[k] = strVal
			}
		}
	}

	// 2. Verify Application exists and is active
	app, err := p.store.GetApplicationBySlug(ctx, req.AppSlug)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return p.recordAndReturn(ctx, req, nil, &domain.AuthorizeResponse{
				Allowed:     false,
				Decision:    string(domain.EffectDeny),
				Reason:      "application_not_found",
				EvaluatedAt: now,
			}), nil
		}
		return nil, fmt.Errorf("fetch application: %w", err)
	}

	if !app.IsActive {
		return p.recordAndReturn(ctx, req, &app.ID, &domain.AuthorizeResponse{
			Allowed:     false,
			Decision:    string(domain.EffectDeny),
			Reason:      "application_inactive",
			EvaluatedAt: now,
		}), nil
	}

	if app.RequireMFA && !req.Context.MFAVerified {
		return p.recordAndReturn(ctx, req, &app.ID, &domain.AuthorizeResponse{
			Allowed:     false,
			Decision:    string(domain.EffectDeny),
			Reason:      "application_requires_mfa",
			EvaluatedAt: now,
		}), nil
	}

	// 3. Query matching grants from PostgreSQL
	grants, err := p.store.FindMatchingGrants(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("query matching grants: %w", err)
	}

	if len(grants) == 0 {
		return p.recordAndReturn(ctx, req, &app.ID, &domain.AuthorizeResponse{
			Allowed:     false,
			Decision:    string(domain.EffectDeny),
			Reason:      "no_matching_grant",
			EvaluatedAt: now,
		}), nil
	}

	// 4. First Pass: Check for any applicable Explicit DENY
	for _, g := range grants {
		if g.Effect == domain.EffectDeny {
			// If the deny rule has ABAC conditions, it applies when those conditions match
			assignOK, _ := EvaluateConditions(g.AssignmentConditions, req.Context)
			permOK, _ := EvaluateConditions(g.PermissionConditions, req.Context)
			if assignOK && permOK {
				assignID := g.AssignmentID
				return p.recordAndReturn(ctx, req, &app.ID, &domain.AuthorizeResponse{
					Allowed:      false,
					Decision:     string(domain.EffectDeny),
					Reason:       "explicit_deny_rule",
					MatchedRole:  g.RoleSlug,
					AssignmentID: &assignID,
					EvaluatedAt:  now,
				}), nil
			}
		}
	}

	// 5. Second Pass: Check for any ALLOW grant that satisfies all ABAC conditions
	var lastABACFailure string
	for _, g := range grants {
		if g.Effect == domain.EffectAllow {
			if ok, reason := EvaluateConditions(g.AssignmentConditions, req.Context); !ok {
				lastABACFailure = reason
				continue
			}
			if ok, reason := EvaluateConditions(g.PermissionConditions, req.Context); !ok {
				lastABACFailure = reason
				continue
			}
			assignID := g.AssignmentID
			return p.recordAndReturn(ctx, req, &app.ID, &domain.AuthorizeResponse{
				Allowed:      true,
				Decision:     string(domain.EffectAllow),
				Reason:       "grant_matched",
				MatchedRole:  g.RoleSlug,
				AssignmentID: &assignID,
				EvaluatedAt:  now,
			}), nil
		}
	}

	denyReason := "no_matching_grant"
	if lastABACFailure != "" {
		denyReason = "abac_condition_failed:" + lastABACFailure
	}

	return p.recordAndReturn(ctx, req, &app.ID, &domain.AuthorizeResponse{
		Allowed:     false,
		Decision:    string(domain.EffectDeny),
		Reason:      denyReason,
		EvaluatedAt: now,
	}), nil
}

// BatchAuthorize evaluates multiple resource/action checks for the same Principal and Application.
func (p *PDP) BatchAuthorize(ctx context.Context, batchReq domain.BatchAuthorizeRequest) (*domain.BatchAuthorizeResponse, error) {
	results := make(map[string]domain.AuthorizeResponse, len(batchReq.Checks))
	for _, item := range batchReq.Checks {
		singleReq := domain.AuthorizeRequest{
			PrincipalID:    batchReq.PrincipalID,
			AppSlug:        batchReq.AppSlug,
			ResourceType:   item.ResourceType,
			ResourceID:     item.ResourceID,
			Action:         item.Action,
			OrganizationID: item.OrganizationID,
			Context:        batchReq.Context,
		}
		res, err := p.Authorize(ctx, singleReq)
		if err != nil {
			return nil, err
		}
		results[item.CheckID] = *res
	}
	return &domain.BatchAuthorizeResponse{Results: results}, nil
}

func (p *PDP) recordAndReturn(
	ctx context.Context,
	req domain.AuthorizeRequest,
	appID *uuid.UUID,
	resp *domain.AuthorizeResponse,
) *domain.AuthorizeResponse {
	_ = p.store.InsertAuditLog(ctx, domain.AuditLog{
		ActorUserID:   &req.PrincipalID,
		ActorIP:       req.Context.ClientIP,
		ApplicationID: appID,
		EventType:     "authz.check",
		TargetType:    req.ResourceType,
		TargetID:      req.ResourceID,
		Decision:      resp.Decision,
		Payload: map[string]any{
			"app_slug":        req.AppSlug,
			"action":          req.Action,
			"organization_id": req.OrganizationID,
			"reason":          resp.Reason,
			"matched_role":    resp.MatchedRole,
			"assignment_id":   resp.AssignmentID,
			"mfa_verified":    req.Context.MFAVerified,
		},
	})
	return resp
}
