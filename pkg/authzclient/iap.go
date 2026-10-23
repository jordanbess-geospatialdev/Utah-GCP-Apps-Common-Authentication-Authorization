package authzclient

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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

// IAPTokenExchange returns middleware for downstream applications fronted by Google Cloud
// Identity-Aware Proxy. On every inbound request it reads the signed IAP assertion header,
// exchanges it for this application's Zero Trust JWT via POST /v1/auth/token, and injects it
// as the Authorization Bearer credential so downstream middleware (RequirePermission) works
// unchanged. Exchanged tokens are cached per IAP subject until shortly before expiry.
//
// Chain it OUTSIDE RequirePermission:
//
//	handler := client.IAPTokenExchange(nil)(client.RequirePermission("basin_layer", "read", nil)(mux))
//
// When the IAP header is absent the request passes through untouched, so deployments that
// also accept direct Bearer tokens (e.g., service-to-service calls) keep working; when the
// header is present the IAP-verified identity always replaces any client-supplied Bearer token.
func (c *Client) IAPTokenExchange(organizationID *uuid.UUID) func(http.Handler) http.Handler {
	cache := &iapTokenCache{entries: make(map[string]iapCacheEntry)}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertion := r.Header.Get(IAPAssertionHeader)
			if assertion == "" {
				next.ServeHTTP(w, r)
				return
			}

			cacheKey := iapCacheKey(assertion)
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

// iapCacheKey derives a stable cache key from the assertion's subject and audience without
// verifying it: IAP re-signs the assertion on every request (fresh iat/exp), so the raw token
// is not a usable key. Cache entries are only created AFTER the authz service has
// cryptographically verified the assertion, so a forged sub can only cause a cache miss.
func iapCacheKey(assertion string) string {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return assertion
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return assertion
	}
	var claims struct {
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Sub == "" {
		return assertion
	}
	aud := strings.Trim(strings.Join(strings.Fields(string(claims.Aud)), ""), `",[]`)
	return claims.Sub + "|" + aud
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
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return "", "", "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", "", false
	}
	var claims struct {
		Sub   string          `json:"sub"`
		Aud   json.RawMessage `json:"aud"`
		Email string          `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Sub == "" {
		return "", "", "", false
	}
	aud = strings.Trim(strings.Join(strings.Fields(string(claims.Aud)), ""), `",[]`)
	return claims.Sub, aud, claims.Email, true
}
