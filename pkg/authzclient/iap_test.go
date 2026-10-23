package authzclient_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/utah-dnr/utah-gcp-common-authz/pkg/authzclient"
)

// fakeIAPAssertion builds an unsigned JWT-shaped string with the given sub/aud claims;
// the middleware never verifies the signature itself (the authz service does on exchange).
func fakeIAPAssertion(sub, aud string) string {
	payload, _ := json.Marshal(map[string]any{"sub": sub, "aud": aud, "email": sub})
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"test"}`)) +
		"." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
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

func TestIAPTokenExchangeMiddleware(t *testing.T) {
	var exchanges int32
	tokens := make(chan string, 8)
	tokens <- "app-jwt-1"
	tokens <- "app-jwt-2"
	fake := newFakeAuthzService(t, &exchanges, tokens)
	defer fake.Close()

	client := authzclient.NewClient(fake.URL, "water-map")
	var sawAuth string
	handler := client.IAPTokenExchange(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))

	// First request: exchange happens and Bearer token is injected
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(authzclient.IAPAssertionHeader, fakeIAPAssertion("accounts.google.com:carol@utah.gov", "/projects/1/services/water-map"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if sawAuth != "Bearer app-jwt-1" {
		t.Fatalf("Authorization = %q, want Bearer app-jwt-1", sawAuth)
	}

	// Second request with a re-signed (different raw) assertion but same sub+aud: served from cache
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set(authzclient.IAPAssertionHeader, fakeIAPAssertion("accounts.google.com:carol@utah.gov", "/projects/1/services/water-map")+"x")
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

func TestIAPTokenExchangeMiddlewareRejectsFailedExchange(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer fake.Close()

	client := authzclient.NewClient(fake.URL, "water-map")
	handler := client.IAPTokenExchange(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("downstream handler must not run when exchange fails")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(authzclient.IAPAssertionHeader, fakeIAPAssertion("accounts.google.com:mallory@example.com", "/projects/1/services/water-map"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestIAPIdentityFromAssertion(t *testing.T) {
	sub, aud, email, ok := authzclient.IAPIdentityFromAssertion(fakeIAPAssertion("carol@utah.gov", "/projects/1/services/water-map"))
	if !ok || sub != "carol@utah.gov" || aud != "/projects/1/services/water-map" || email != "carol@utah.gov" {
		t.Fatalf("got (%q,%q,%q,%v)", sub, aud, email, ok)
	}
	if _, _, _, ok := authzclient.IAPIdentityFromAssertion("not-a-jwt"); ok {
		t.Fatal("expected ok=false for malformed assertion")
	}
}
