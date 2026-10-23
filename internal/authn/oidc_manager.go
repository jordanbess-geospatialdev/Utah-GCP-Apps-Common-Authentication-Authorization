package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/db"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
)

// VerifiedIdentity represents the cryptographically verified claims from UtahID or an external OIDC IdP.
type VerifiedIdentity struct {
	IdP           *domain.IdentityProvider
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
	Groups        []string
	MFAVerified   bool
	RawClaims     map[string]any
}

// UpstreamTokenVerifier verifies an upstream OIDC ID token and extracts normalized claims.
type UpstreamTokenVerifier interface {
	VerifyUpstreamToken(ctx context.Context, rawToken string) (*VerifiedIdentity, error)
}

// MultiIssuerOIDCVerifier dynamically verifies OIDC tokens from UtahID and registered External IdPs.
type MultiIssuerOIDCVerifier struct {
	store     db.Store
	mu        sync.RWMutex
	verifiers map[string]issuerVerifier // keyed by issuer_url
}

// issuerVerifier couples a cached go-oidc verifier with the audiences accepted for that issuer.
// A single IdP row can list several comma-separated audiences in client_id, which is required
// for Google IAP where one issuer (https://cloud.google.com/iap) fronts multiple backend
// services, each asserting its own '/projects/...' audience.
type issuerVerifier struct {
	verifier          *oidc.IDTokenVerifier
	acceptedAudiences []string // >1 entry means go-oidc skips its single-aud check and we enforce membership manually
}

// NewMultiIssuerOIDCVerifier creates a new multi-issuer OIDC verifier backed by the Store.
func NewMultiIssuerOIDCVerifier(store db.Store) *MultiIssuerOIDCVerifier {
	return &MultiIssuerOIDCVerifier{
		store:     store,
		verifiers: make(map[string]issuerVerifier),
	}
}

// VerifyUpstreamToken inspects the token's 'iss' claim, resolves the trusted IdentityProvider from Postgres,
// verifies the cryptographic signature & expiry via OIDC JWKS, and normalizes claims via ClaimMappings.
func (v *MultiIssuerOIDCVerifier) VerifyUpstreamToken(ctx context.Context, rawToken string) (*VerifiedIdentity, error) {
	issuer, err := peekTokenIssuer(rawToken)
	if err != nil {
		return nil, fmt.Errorf("invalid jwt format: %w", err)
	}

	idp, err := v.store.GetIdentityProviderByIssuer(ctx, issuer)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, fmt.Errorf("untrusted oidc issuer %q: %w", issuer, db.ErrUnauthorized)
		}
		return nil, fmt.Errorf("lookup identity provider: %w", err)
	}
	if !idp.IsActive {
		return nil, fmt.Errorf("identity provider %q is disabled: %w", idp.Slug, db.ErrUnauthorized)
	}

	iv, err := v.getOrCreateVerifier(ctx, idp)
	if err != nil {
		return nil, fmt.Errorf("initialize oidc verifier for %q: %w", idp.Slug, err)
	}

	idToken, err := iv.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("verify oidc token signature/claims: %w", err)
	}

	var rawClaims map[string]any
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("decode oidc claims: %w", err)
	}

	if len(iv.acceptedAudiences) > 1 {
		if err := assertAcceptedAudience(rawClaims, iv.acceptedAudiences); err != nil {
			return nil, err
		}
	}

	return ExtractNormalizedIdentity(idp, idToken.Subject, rawClaims), nil
}

func (v *MultiIssuerOIDCVerifier) getOrCreateVerifier(ctx context.Context, idp *domain.IdentityProvider) (issuerVerifier, error) {
	v.mu.RLock()
	cached, ok := v.verifiers[idp.IssuerURL]
	v.mu.RUnlock()
	if ok {
		return cached, nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if cached, ok := v.verifiers[idp.IssuerURL]; ok {
		return cached, nil
	}

	acceptedAudiences := splitAcceptedAudiences(idp.ClientID)
	cfg := &oidc.Config{}
	switch {
	case len(acceptedAudiences) == 1:
		cfg = &oidc.Config{ClientID: acceptedAudiences[0]}
	case len(acceptedAudiences) > 1:
		cfg = &oidc.Config{SkipClientIDCheck: true}
	}

	var verifier *oidc.IDTokenVerifier
	if idp.JWKSURI != "" {
		keySet := oidc.NewRemoteKeySet(ctx, idp.JWKSURI)
		verifier = oidc.NewVerifier(idp.IssuerURL, keySet, cfg)
	} else {
		provider, err := oidc.NewProvider(ctx, idp.IssuerURL)
		if err != nil {
			return issuerVerifier{}, err
		}
		verifier = provider.Verifier(cfg)
	}

	entry := issuerVerifier{verifier: verifier, acceptedAudiences: acceptedAudiences}
	v.verifiers[idp.IssuerURL] = entry
	return entry, nil
}

// splitAcceptedAudiences parses a comma-separated client_id into distinct audiences.
// Single-audience rows keep go-oidc's native audience check; multi-audience rows
// (e.g., several IAP-protected services under one issuer) are membership-checked after verify.
func splitAcceptedAudiences(clientID string) []string {
	parts := strings.Split(clientID, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// assertAcceptedAudience enforces that at least one token 'aud' value (string or array)
// matches an accepted audience. Only used when the IdP declares multiple audiences.
func assertAcceptedAudience(rawClaims map[string]any, accepted []string) error {
	auds := stringOrSliceClaim(rawClaims["aud"])
	for _, aud := range auds {
		for _, want := range accepted {
			if aud == want {
				return nil
			}
		}
	}
	return fmt.Errorf("token audience %v not in accepted audiences for issuer: %w", auds, db.ErrUnauthorized)
}

func stringOrSliceClaim(val any) []string {
	switch v := val.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}

// ExtractNormalizedIdentity maps raw OIDC claims into a canonical VerifiedIdentity using idp.ClaimMappings.
func ExtractNormalizedIdentity(idp *domain.IdentityProvider, defaultSub string, rawClaims map[string]any) *VerifiedIdentity {
	mappings := idp.ClaimMappings
	sub := getStringClaim(rawClaims, defaultIfEmpty(mappings.Subject, "sub"))
	if sub == "" {
		sub = defaultSub
	}
	email := getStringClaim(rawClaims, defaultIfEmpty(mappings.Email, "email"))
	name := getStringClaim(rawClaims, defaultIfEmpty(mappings.Name, "name"))
	if name == "" {
		name = email
	}

	emailVerified := true
	if ev, ok := rawClaims["email_verified"].(bool); ok {
		emailVerified = ev
	}

	groups := getStringSliceClaim(rawClaims, defaultIfEmpty(mappings.Groups, "groups"))
	mfaVerified := detectMFAClaim(rawClaims, defaultIfEmpty(mappings.MFA, "amr"))

	return &VerifiedIdentity{
		IdP:           idp,
		Subject:       sub,
		Email:         email,
		EmailVerified: emailVerified,
		DisplayName:   name,
		Groups:        groups,
		MFAVerified:   mfaVerified,
		RawClaims:     rawClaims,
	}
}

func peekTokenIssuer(rawToken string) (string, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return "", errors.New("token must have 3 segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	if claims.Issuer == "" {
		return "", errors.New("missing iss claim")
	}
	return claims.Issuer, nil
}

func getStringClaim(claims map[string]any, path string) string {
	val := lookupNestedClaim(claims, path)
	if s, ok := val.(string); ok {
		return s
	}
	return ""
}

func getStringSliceClaim(claims map[string]any, path string) []string {
	val := lookupNestedClaim(claims, path)
	switch v := val.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

func detectMFAClaim(claims map[string]any, path string) bool {
	val := lookupNestedClaim(claims, path)
	switch v := val.(type) {
	case bool:
		return v
	case string:
		lower := strings.ToLower(v)
		return lower != "" && lower != "pwd" && lower != "password" && lower != "none"
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				lower := strings.ToLower(s)
				if lower == "mfa" || lower == "otp" || lower == "totp" || lower == "webauthn" || lower == "hwk" || lower == "sms" {
					return true
				}
			}
		}
	case []string:
		for _, s := range v {
			lower := strings.ToLower(s)
			if lower == "mfa" || lower == "otp" || lower == "totp" || lower == "webauthn" || lower == "hwk" || lower == "sms" {
				return true
			}
		}
	}
	return false
}

func lookupNestedClaim(claims map[string]any, dottedPath string) any {
	parts := strings.Split(dottedPath, ".")
	var cur any = claims
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

func defaultIfEmpty(val, fallback string) string {
	if val != "" {
		return val
	}
	return fallback
}
