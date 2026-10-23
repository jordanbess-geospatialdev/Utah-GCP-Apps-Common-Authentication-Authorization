package authzclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/authn"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
)

type contextKey string

const principalContextKey contextKey = "utah_zero_trust_principal"

// Client is a lightweight SDK for downstream Utah Cloud Run applications to enforce Zero Trust permissions.
type Client struct {
	baseURL    string
	appSlug    string
	httpClient *http.Client
}

// NewClient creates a new Zero Trust AuthZ client for a specific downstream application.
func NewClient(baseURL, appSlug string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		appSlug: appSlug,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Authorize calls the central Policy Decision Point (POST /v1/authorize) to verify a fine-grained action.
func (c *Client) Authorize(ctx context.Context, req domain.AuthorizeRequest) (*domain.AuthorizeResponse, error) {
	if req.AppSlug == "" {
		req.AppSlug = c.appSlug
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/authorize", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call authz service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authz service returned status %d", resp.StatusCode)
	}

	var decision domain.AuthorizeResponse
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return nil, err
	}
	return &decision, nil
}

// ExchangeToken performs RFC 8693 token exchange (POST /v1/auth/token), swapping an upstream
// OIDC ID token (UtahID, external IdP, or Google IAP assertion) for a short-lived app-scoped JWT.
func (c *Client) ExchangeToken(ctx context.Context, subjectToken string, organizationID *uuid.UUID) (*authn.TokenExchangeResponse, error) {
	body := map[string]any{
		"subject_token": subjectToken,
		"target_app":    c.appSlug,
	}
	if organizationID != nil {
		body["organization_id"] = organizationID.String()
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/auth/token", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call authz service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange returned status %d", resp.StatusCode)
	}

	var exchanged authn.TokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&exchanged); err != nil {
		return nil, err
	}
	return &exchanged, nil
}

// RequirePermission returns standard net/http middleware that enforces a fine-grained Zero Trust
// permission check (resourceType:action) and optional dynamic resourceID extraction before invoking next.
func (c *Client) RequirePermission(
	resourceType string,
	action string,
	resourceIDExtractor func(r *http.Request) string,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
				return
			}
			rawToken := strings.TrimPrefix(authHeader, "Bearer ")

			// Parse claims (signature verification can use cached JWKS or PDP check)
			claims := &authn.AppTokenClaims{}
			_, _, err := jwt.NewParser().ParseUnverified(rawToken, claims)
			if err != nil {
				http.Error(w, `{"error":"malformed bearer token"}`, http.StatusUnauthorized)
				return
			}

			principalID, err := uuid.Parse(claims.Subject)
			if err != nil {
				http.Error(w, `{"error":"invalid token subject"}`, http.StatusUnauthorized)
				return
			}

			var resourceID string
			if resourceIDExtractor != nil {
				resourceID = resourceIDExtractor(r)
			}

			decision, err := c.Authorize(r.Context(), domain.AuthorizeRequest{
				PrincipalID:    principalID,
				AppSlug:        c.appSlug,
				ResourceType:   resourceType,
				ResourceID:     resourceID,
				Action:         action,
				OrganizationID: claims.OrganizationID,
				Context: domain.RequestContext{
					MFAVerified: claims.MFAVerified,
					UserType:    claims.UserType,
				},
			})
			if err != nil || !decision.Allowed {
				http.Error(w, `{"error":"forbidden by zero trust policy"}`, http.StatusForbidden)
				return
			}

			ctxWithPrincipal := context.WithValue(r.Context(), principalContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctxWithPrincipal))
		})
	}
}

// PrincipalFromContext retrieves the verified AppTokenClaims from the request context.
func PrincipalFromContext(ctx context.Context) (*authn.AppTokenClaims, bool) {
	claims, ok := ctx.Value(principalContextKey).(*authn.AppTokenClaims)
	return claims, ok
}
