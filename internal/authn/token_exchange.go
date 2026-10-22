package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/db"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
)

// AppTokenClaims represents the Zero Trust claims embedded in an exchanged, app-scoped JWT.
type AppTokenClaims struct {
	jwt.RegisteredClaims
	Email          string     `json:"email,omitempty"`
	DisplayName    string     `json:"name,omitempty"`
	UserType       string     `json:"user_type"`
	IdentitySource string     `json:"idp"`
	MFAVerified    bool       `json:"mfa"`
	OrganizationID *uuid.UUID `json:"org_id,omitempty"`
	Roles          []string   `json:"roles"`
}

// TokenExchangeRequest follows RFC 8693 semantics for exchanging an upstream IdP token
// for an application-scoped Zero Trust token.
type TokenExchangeRequest struct {
	SubjectToken   string     `json:"subject_token"`            // Upstream OIDC token from UtahID or External IdP
	TargetAppSlug  string     `json:"target_app"`               // Target application slug (becomes 'aud')
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"` // Optional active organization/agency scope
	ClientIP       string     `json:"-"`
}

// TokenExchangeResponse returns the short-lived application JWT and metadata.
type TokenExchangeResponse struct {
	AccessToken     string      `json:"access_token"`
	IssuedTokenType string      `json:"issued_token_type"`
	TokenType       string      `json:"token_type"`
	ExpiresIn       int         `json:"expires_in"`
	AppSlug         string      `json:"app_slug"`
	User            domain.User `json:"user"`
	Roles           []string    `json:"roles"`
}

// JWK represents a single JSON Web Key in /.well-known/jwks.json.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKS represents a JSON Web Key Set document.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// TokenService manages RFC 8693 token exchange, ES256 JWT signing, and JWKS publication.
type TokenService struct {
	store      db.Store
	verifier   UpstreamTokenVerifier
	issuerURL  string
	keyID      string
	privateKey *ecdsa.PrivateKey
}

// NewTokenService initializes the TokenService using a PEM-encoded ECDSA P-256 private key
// (or generates an ephemeral P-256 key pair if privateKeyPEM is empty).
func NewTokenService(
	store db.Store,
	verifier UpstreamTokenVerifier,
	issuerURL string,
	keyID string,
	privateKeyPEM string,
) (*TokenService, error) {
	var privKey *ecdsa.PrivateKey
	var err error

	if privateKeyPEM != "" {
		privKey, err = parseECPrivateKeyFromPEM(privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse signing private key: %w", err)
		}
	} else {
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ecdsa p256 key: %w", err)
		}
	}

	if keyID == "" {
		keyID = "utah-authz-es256-1"
	}

	return &TokenService{
		store:      store,
		verifier:   verifier,
		issuerURL:  issuerURL,
		keyID:      keyID,
		privateKey: privKey,
	}, nil
}

// ExchangeToken validates an upstream UtahID or External OIDC token and issues a short-lived,
// audience-restricted JWT scoped to the target application.
func (s *TokenService) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (*TokenExchangeResponse, error) {
	if req.SubjectToken == "" || req.TargetAppSlug == "" {
		return nil, fmt.Errorf("subject_token and target_app are required: %w", db.ErrUnauthorized)
	}

	// 1. Cryptographically verify the upstream OIDC token (UtahID or External IdP)
	verifiedId, err := s.verifier.VerifyUpstreamToken(ctx, req.SubjectToken)
	if err != nil {
		return nil, fmt.Errorf("upstream token verification failed: %w", err)
	}

	// 2. Lookup target Application and verify it is active
	app, err := s.store.GetApplicationBySlug(ctx, req.TargetAppSlug)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, fmt.Errorf("target application %q not found: %w", req.TargetAppSlug, db.ErrNotFound)
		}
		return nil, err
	}
	if !app.IsActive {
		return nil, fmt.Errorf("target application %q is inactive: %w", req.TargetAppSlug, db.ErrUnauthorized)
	}

	// 3. Verify that the target Application trusts this Identity Provider
	appIdP, err := s.store.GetAppIdentityProvider(ctx, app.ID, verifiedId.IdP.ID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, fmt.Errorf("identity provider %q is not authorized for application %q: %w",
				verifiedId.IdP.Slug, app.Slug, db.ErrUnauthorized)
		}
		return nil, err
	}

	// 4. Enforce Application-level MFA requirement before issuing an App Token
	if app.RequireMFA && !verifiedId.MFAVerified {
		return nil, fmt.Errorf("application %q requires Multi-Factor Authentication (MFA): %w",
			app.Slug, db.ErrUnauthorized)
	}

	// 5. Resolve or JIT-provision the canonical User and sync mapped OIDC groups
	user, err := s.store.ResolveOrProvisionUser(
		ctx,
		verifiedId.IdP,
		verifiedId.Subject,
		verifiedId.Email,
		verifiedId.DisplayName,
		verifiedId.EmailVerified,
		verifiedId.RawClaims,
		verifiedId.Groups,
	)
	if err != nil {
		return nil, err
	}

	if user.Status != domain.UserStatusActive {
		return nil, fmt.Errorf("user account status is %q: %w", user.Status, db.ErrUnauthorized)
	}

	// 6. Query active baseline roles for this User + App (+ optional Organization)
	roles, err := s.store.ListUserActiveRolesForApp(ctx, user.ID, app.ID, req.OrganizationID)
	if err != nil {
		return nil, fmt.Errorf("query user active roles: %w", err)
	}

	// If JIT signup is enabled on this App-IdP binding and the user has no roles yet, assign the default role
	if len(roles) == 0 && appIdP.AllowJITSignup && appIdP.DefaultRoleID != nil {
		_, err := s.store.CreateRoleAssignment(ctx, domain.RoleAssignment{
			ApplicationID: app.ID,
			RoleID:        *appIdP.DefaultRoleID,
			PrincipalType: domain.PrincipalUser,
			UserID:        &user.ID,
			Effect:        domain.EffectAllow,
			Justification: "Automatic JIT default role assignment via " + verifiedId.IdP.Slug,
		})
		if err == nil {
			roles, _ = s.store.ListUserActiveRolesForApp(ctx, user.ID, app.ID, req.OrganizationID)
		}
	}
	if roles == nil {
		roles = []string{}
	}

	// 7. Sign short-lived Zero Trust JWT scoped strictly to target_app
	now := time.Now().UTC()
	ttl := time.Duration(app.TokenTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	claims := AppTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuerURL,
			Subject:   user.ID.String(),
			Audience:  jwt.ClaimStrings{app.Slug},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.NewString(),
		},
		Email:          user.Email,
		DisplayName:    user.DisplayName,
		UserType:       user.UserType,
		IdentitySource: verifiedId.IdP.Slug,
		MFAVerified:    verifiedId.MFAVerified,
		OrganizationID: req.OrganizationID,
		Roles:          roles,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = s.keyID

	signedJWT, err := token.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign app jwt: %w", err)
	}

	// 8. Record token exchange in immutable audit log
	_ = s.store.InsertAuditLog(ctx, domain.AuditLog{
		ActorUserID:   &user.ID,
		ActorIP:       req.ClientIP,
		ApplicationID: &app.ID,
		EventType:     "authn.token_exchange",
		TargetType:    "application",
		TargetID:      app.Slug,
		Decision:      "allow",
		Payload: map[string]any{
			"idp_slug":        verifiedId.IdP.Slug,
			"mfa_verified":    verifiedId.MFAVerified,
			"organization_id": req.OrganizationID,
			"roles_issued":    roles,
			"ttl_seconds":     int(ttl.Seconds()),
		},
	})

	return &TokenExchangeResponse{
		AccessToken:     signedJWT,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl.Seconds()),
		AppSlug:         app.Slug,
		User:            *user,
		Roles:           roles,
	}, nil
}

// VerifyAppToken validates an exchanged App JWT and enforces that its 'aud' matches expectedAppSlug (if non-empty).
func (s *TokenService) VerifyAppToken(rawToken string, expectedAppSlug string) (*AppTokenClaims, error) {
	claims := &AppTokenClaims{}
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(s.issuerURL),
	}
	if expectedAppSlug != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(expectedAppSlug))
	}

	token, err := jwt.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (any, error) {
		return &s.privateKey.PublicKey, nil
	}, parserOpts...)
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid app token: %w", err)
	}
	return claims, nil
}

// PublicJWKS returns the JSON Web Key Set containing our active P-256 public key.
func (s *TokenService) PublicJWKS() JWKS {
	pub := s.privateKey.PublicKey
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := pub.X.FillBytes(make([]byte, byteLen))
	yBytes := pub.Y.FillBytes(make([]byte, byteLen))

	return JWKS{
		Keys: []JWK{
			{
				Kty: "EC",
				Crv: "P-256",
				Use: "sig",
				Alg: "ES256",
				Kid: s.keyID,
				X:   base64.RawURLEncoding.EncodeToString(xBytes),
				Y:   base64.RawURLEncoding.EncodeToString(yBytes),
			},
		},
	}
}

func parseECPrivateKeyFromPEM(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ECDSA")
	}
	return ecKey, nil
}
