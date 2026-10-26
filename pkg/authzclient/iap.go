package authzclient

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
)

// IAPAssertionHeader carries the Google Cloud Identity-Aware Proxy signed JWT assertion.
// Header lookup is case-insensitive, so IAP's canonical "X-Goog-Iap-Jwt-Assertion" matches too.
const IAPAssertionHeader = "X-Goog-IAP-JWT-Assertion"

// iapCacheSkew is subtracted from the exchanged token TTL so a cached entry is never
// served in the window where the authz service would already consider it expired.
const iapCacheSkew = 30 * time.Second

// iapMaxCacheEntries bounds the per-instance exchange cache (Cloud Run instances are
// single-process; entries are keyed by IAP subject+audience, one per active user).
const iapMaxCacheEntries = 4096

// iapAssertionClaims is the claim set Google IAP embeds in its signed header assertions.
type iapAssertionClaims struct {
	jwt.RegisteredClaims
	Email string `json:"email,omitempty"`
}

// IAPTokenExchange returns middleware for downstream applications fronted by Google Cloud
// Identity-Aware Proxy. On every inbound request it reads the signed IAP assertion header,
// verifies its signature against Google IAP's published public keys, exchanges it for this
// application's Zero Trust JWT via POST /v1/auth/token, and injects it as the Authorization
// Bearer credential so downstream middleware (RequirePermission) works unchanged.
// Exchanged tokens are cached per verified IAP subject+audience until shortly before expiry.
//
// Chain it OUTSIDE RequirePermission:
//
//	handler := client.IAPTokenExchange(nil)(client.RequirePermission("basin_layer", "read", nil)(mux))
//
// When the IAP header is absent the request passes through untouched, so deployments that
// also accept direct Bearer tokens (e.g., service-to-service calls) keep working; when the
// header is present it is locally signature-verified first (so a forged assertion can never
// be used to look up another user's cached token) and the IAP-verified identity always
// replaces any client-supplied Bearer token.
func (c *Client) IAPTokenExchange(organizationID *uuid.UUID) func(http.Handler) http.Handler {
	cache := &iapTokenCache{entries: make(map[string]iapCacheEntry)}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertion := r.Header.Get(IAPAssertionHeader)
			if assertion == "" {
				next.ServeHTTP(w, r)
				return
			}

			sub, aud, err := c.verifyIAPAssertion(r.Context(), assertion)
			if err != nil {
				http.Error(w, `{"error":"iap assertion failed signature verification"}`, http.StatusUnauthorized)
				return
			}

			cacheKey := sub + "|" + aud
			if token, ok := cache.get(cacheKey); ok {
				r.Header.Set("Authorization", "Bearer "+token)
				next.ServeHTTP(w, r)
				return
			}

			exchanged, err := c.ExchangeToken(r.Context(), assertion, organizationID)
			if err != nil {
				http.Error(w, `{"error":"iap assertion rejected by authz service"}`, http.StatusUnauthorized)
				return
			}
			cache.put(cacheKey, exchanged.AccessToken, time.Duration(exchanged.ExpiresIn)*time.Second)

			r.Header.Set("Authorization", "Bearer "+exchanged.AccessToken)
			next.ServeHTTP(w, r)
		})
	}
}

// verifyIAPAssertion locally verifies an IAP assertion's signature (ES256 or RS256 against
// Google's published JWKS), its fixed issuer, and its expiry. Audience checking stays with
// the authz service, which knows which IAP service audiences this application accepts.
// Only claims from assertions that pass this verification may be used as cache keys: a
// forged assertion cannot produce another user's cache entry because it cannot carry a
// valid Google signature over a chosen subject.
func (c *Client) verifyIAPAssertion(ctx context.Context, assertion string) (sub, aud string, err error) {
	claims := &iapAssertionClaims{}
	token, err := jwt.ParseWithClaims(
		assertion,
		claims,
		c.iapKeys.keyFunc(ctx, jwt.SigningMethodES256.Alg(), jwt.SigningMethodRS256.Alg()),
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg(), jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(domain.IAPIssuerURL),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		return "", "", fmt.Errorf("verify iap assertion: %w", err)
	}
	if claims.Subject == "" || len(claims.Audience) == 0 {
		return "", "", fmt.Errorf("iap assertion missing sub/aud claims")
	}
	return claims.Subject, strings.Join(claims.Audience, ","), nil
}

type iapCacheEntry struct {
	token     string
	expiresAt time.Time
}

type iapTokenCache struct {
	mu      sync.Mutex
	entries map[string]iapCacheEntry
}

func (c *iapTokenCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiresAt) {
		delete(c.entries, key)
		return "", false
	}
	return entry.token, true
}

func (c *iapTokenCache) put(key, token string, ttl time.Duration) {
	ttl -= iapCacheSkew
	if ttl < 0 {
		ttl = 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= iapMaxCacheEntries {
		now := time.Now()
		for k, e := range c.entries {
			if now.After(e.expiresAt) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= iapMaxCacheEntries {
			for k := range c.entries { // still full: drop one arbitrary entry
				delete(c.entries, k)
				break
			}
		}
	}
	c.entries[key] = iapCacheEntry{token: token, expiresAt: time.Now().Add(ttl)}
}

// IAPIdentityFromAssertion extracts the unverified subject/email/audience from an IAP
// assertion for logging or request correlation. It performs NO signature validation;
// security decisions must go through IAPTokenExchange + RequirePermission.
func IAPIdentityFromAssertion(assertion string) (sub, aud, email string, ok bool) {
	decoded, err := decodeAssertionPayload(assertion)
	if err != nil || decoded.Subject == "" {
		return "", "", "", false
	}
	return decoded.Subject, strings.Join(decoded.Audience, ","), decoded.Email, true
}

// decodeAssertionPayload parses an assertion's payload without any verification.
func decodeAssertionPayload(assertion string) (*iapAssertionClaims, error) {
	claims := &iapAssertionClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(assertion, claims); err != nil {
		return nil, err
	}
	return claims, nil
}
