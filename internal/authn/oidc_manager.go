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
	verifiers map[string]*oidc.IDTokenVerifier // keyed by issuer_url
}

// NewMultiIssuerOIDCVerifier creates a new multi-issuer OIDC verifier backed by the Store.
func NewMultiIssuerOIDCVerifier(store db.Store) *MultiIssuerOIDCVerifier {
	return &MultiIssuerOIDCVerifier{
		store:     store,
		verifiers: make(map[string]*oidc.IDTokenVerifier),
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

	verifier, err := v.getOrCreateVerifier(ctx, idp)
	if err != nil {
		return nil, fmt.Errorf("initialize oidc verifier for %q: %w", idp.Slug, err)
	}

	idToken, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("verify oidc token signature/claims: %w", err)
	}

	var rawClaims map[string]any
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("decode oidc claims: %w", err)
	}

	return ExtractNormalizedIdentity(idp, idToken.Subject, rawClaims), nil
}

func (v *MultiIssuerOIDCVerifier) getOrCreateVerifier(ctx context.Context, idp *domain.IdentityProvider) (*oidc.IDTokenVerifier, error) {
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

	var verifier *oidc.IDTokenVerifier
	if idp.JWKSURI != "" {
		keySet := oidc.NewRemoteKeySet(ctx, idp.JWKSURI)
		verifier = oidc.NewVerifier(idp.IssuerURL, keySet, &oidc.Config{
			ClientID: idp.ClientID,
		})
	} else {
		provider, err := oidc.NewProvider(ctx, idp.IssuerURL)
		if err != nil {
			return nil, err
		}
		verifier = provider.Verifier(&oidc.Config{
			ClientID: idp.ClientID,
		})
	}

	v.verifiers[idp.IssuerURL] = verifier
	return verifier, nil
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
