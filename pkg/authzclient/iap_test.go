package authzclient_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/utah-dnr/utah-gcp-common-authz/pkg/authzclient"
)

// iapTestKeys holds an ES256 key pair standing in for Google IAP's signing keys.
type iapTestKeys struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func newIAPTestKeys(t *testing.T) *iapTestKeys {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	return &iapTestKeys{priv: priv, kid: "iap-test-key-1"}
}

// jwksJSON publishes the public key in standard JWKS format.
func (k *iapTestKeys) jwksJSON() map[string]any {
	byteLen := (k.priv.Curve.Params().BitSize + 7) / 8
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": k.kid,
			"x": base64.RawURLEncoding.EncodeToString(k.priv.PublicKey.X.FillBytes(make([]byte, byteLen))),
			"y": base64.RawURLEncoding.EncodeToString(k.priv.PublicKey.Y.FillBytes(make([]byte, byteLen))),
		}},
	}
}

// signAssertion produces a properly signed IAP assertion for the given subject/audience.
func (k *iapTestKeys) signAssertion(t *testing.T, sub, aud string) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":   "https://cloud.google.com/iap",
		"sub":   sub,
		"aud":   aud,
		"email": sub,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	token.Header["kid"] = k.kid
	signed, err := token.SignedString(k.priv)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return signed
}

// forgedAssertion builds a JWT-shaped string claiming sub/aud but with no valid signature.
func forgedAssertion(sub, aud string) string {
	payload, _ := json.Marshal(map[string]any{
		"iss": "https://cloud.google.com/iap", "sub": sub, "aud": aud,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"iap-test-key-1"}`)) +
		"." + base64.RawURLEncoding.EncodeToString(payload) +
		"." + base64.RawURLEncoding.EncodeToString([]byte("bm90LXZhbGlk"))
}

// newIAPJWKSServer serves the test key set so the middleware can verify assertions locally.
func newIAPJWKSServer(t *testing.T, keys *iapTestKeys) *httptest.Server {
	t.Helper()
	var fetches int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&fetches, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keys.jwksJSON())
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newFakeAuthzService returns a token-exchange endpoint that hands out rotating fake app JWTs.
func newFakeAuthzService(t *testing.T, exchanges *int32, tokens chan string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token" || r.Method != http.MethodPost {
			t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode exchange body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body["target_app"] != "water-map" {
			t.Errorf("exchange target_app = %v, want water-map", body["target_app"])
		}
		if _, ok := body["subject_token"].(string); !ok {
			t.Errorf("exchange missing string subject_token: %v", body)
		}
		atomic.AddInt32(exchanges, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      <-tokens,
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        900,
			"app_slug":          "water-map",
		})
	}))
}

func newIAPTestClient(t *testing.T, fakeAuthzURL, jwksURL string) *authzclient.Client {
	t.Helper()
	return authzclient.NewClient(fakeAuthzURL, "water-map", authzclient.WithIAPJWKSURL(jwksURL))
}

func TestIAPTokenExchangeMiddleware(t *testing.T) {
	keys := newIAPTestKeys(t)
	jwksSrv := newIAPJWKSServer(t, keys)

	var exchanges int32
	tokens := make(chan string, 8)
	tokens <- "app-jwt-1"
	tokens <- "app-jwt-2"
	fake := newFakeAuthzService(t, &exchanges, tokens)
	defer fake.Close()

	client := newIAPTestClient(t, fake.URL, jwksSrv.URL)
	var sawAuth string
	handler := client.IAPTokenExchange(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))

	// First request: signature verifies locally, exchange happens, Bearer token is injected
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(authzclient.IAPAssertionHeader, keys.signAssertion(t, "accounts.google.com:carol@utah.gov", "/projects/1/services/water-map"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if sawAuth != "Bearer app-jwt-1" {
		t.Fatalf("Authorization = %q, want Bearer app-jwt-1", sawAuth)
	}

	// Second request with a re-signed (different raw) assertion but same verified sub+aud: served from cache
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set(authzclient.IAPAssertionHeader, keys.signAssertion(t, "accounts.google.com:carol@utah.gov", "/projects/1/services/water-map"))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if n := atomic.LoadInt32(&exchanges); n != 1 {
		t.Fatalf("exchange calls = %d, want 1 (second hit must come from cache)", n)
	}

	// No IAP header: request passes through untouched
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("Authorization", "Bearer direct-service-token")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if sawAuth != "Bearer direct-service-token" {
		t.Fatalf("passthrough Authorization = %q, want the caller's original Bearer", sawAuth)
	}
	if n := atomic.LoadInt32(&exchanges); n != 1 {
		t.Fatalf("exchange calls after passthrough = %d, want 1", n)
	}
}

// TestIAPMiddlewareRejectsForgedVictimSubject pins the cache-key impersonation fix: an
// attacker submitting an unsigned assertion carrying the victim's subject must NOT be able
// to read the victim's cached app token — it must be rejected by local signature
// verification before any cache lookup.
func TestIAPMiddlewareRejectsForgedVictimSubject(t *testing.T) {
	keys := newIAPTestKeys(t)
	jwksSrv := newIAPJWKSServer(t, keys)

	var exchanges int32
	tokens := make(chan string, 8)
	tokens <- "victim-app-jwt"
	tokens <- "attacker-should-never-get-this"
	fake := newFakeAuthzService(t, &exchanges, tokens)
	defer fake.Close()

	client := newIAPTestClient(t, fake.URL, jwksSrv.URL)
	var sawAuth string
	handler := client.IAPTokenExchange(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))

	// Victim authenticates normally, priming the cache for their subject
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(authzclient.IAPAssertionHeader, keys.signAssertion(t, "accounts.google.com:victim@utah.gov", "/projects/1/services/water-map"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || sawAuth != "Bearer victim-app-jwt" {
		t.Fatalf("victim priming request failed: status=%d auth=%q", rec.Code, sawAuth)
	}

	// Attacker forges an assertion with the victim's sub (invalid signature): must get 401,
	// never the victim's cached token, and must not trigger an exchange.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set(authzclient.IAPAssertionHeader, forgedAssertion("accounts.google.com:victim@utah.gov", "/projects/1/services/water-map"))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("forged assertion status = %d, want 401", rec2.Code)
	}
	if sawAuth != "Bearer victim-app-jwt" {
		t.Fatalf("authorization observed after attack = %q (handler must not have run with a token)", sawAuth)
	}
	if n := atomic.LoadInt32(&exchanges); n != 1 {
		t.Fatalf("exchange calls = %d, want 1 (forged assertion must not reach the authz service)", n)
	}
}

func TestIAPTokenExchangeMiddlewareRejectsFailedExchange(t *testing.T) {
	keys := newIAPTestKeys(t)
	jwksSrv := newIAPJWKSServer(t, keys)

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer fake.Close()

	client := newIAPTestClient(t, fake.URL, jwksSrv.URL)
	handler := client.IAPTokenExchange(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("downstream handler must not run when exchange fails")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(authzclient.IAPAssertionHeader, keys.signAssertion(t, "accounts.google.com:mallory@example.com", "/projects/1/services/water-map"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestIAPMiddlewareRejectsWrongIssuer ensures assertions signed by a trusted key but
// claiming a foreign issuer are refused.
func TestIAPMiddlewareRejectsWrongIssuer(t *testing.T) {
	keys := newIAPTestKeys(t)
	jwksSrv := newIAPJWKSServer(t, keys)

	var exchanges int32
	tokens := make(chan string, 1)
	fake := newFakeAuthzService(t, &exchanges, tokens)
	defer fake.Close()

	client := newIAPTestClient(t, fake.URL, jwksSrv.URL)
	handler := client.IAPTokenExchange(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("downstream handler must not run for wrong-issuer assertion")
	}))

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://evil.example.com/", "sub": "attacker", "aud": "/projects/1/services/water-map",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	token.Header["kid"] = keys.kid
	signed, err := token.SignedString(keys.priv)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(authzclient.IAPAssertionHeader, signed)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-issuer assertion status = %d, want 401", rec.Code)
	}
}

func TestIAPIdentityFromAssertion(t *testing.T) {
	keys := newIAPTestKeys(t)
	assertion := keys.signAssertion(t, "carol@utah.gov", "/projects/1/services/water-map")
	sub, aud, email, ok := authzclient.IAPIdentityFromAssertion(assertion)
	if !ok || sub != "carol@utah.gov" || aud != "/projects/1/services/water-map" || email != "carol@utah.gov" {
		t.Fatalf("got (%q,%q,%q,%v)", sub, aud, email, ok)
	}
	if _, _, _, ok := authzclient.IAPIdentityFromAssertion("not-a-jwt"); ok {
		t.Fatal("expected ok=false for malformed assertion")
	}
}
