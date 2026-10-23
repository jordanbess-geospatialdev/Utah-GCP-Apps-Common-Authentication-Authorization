package authn

import (
	"errors"
	"testing"

	"github.com/utah-dnr/utah-gcp-common-authz/internal/db"
)

func TestSplitAcceptedAudiences(t *testing.T) {
	cases := []struct {
		clientID string
		want     []string
	}{
		{"utah-dnr-common-auth-client", []string{"utah-dnr-common-auth-client"}},
		{"/projects/1/services/a,/projects/1/services/b", []string{"/projects/1/services/a", "/projects/1/services/b"}},
		{" /projects/1/services/a , /projects/1/services/b ", []string{"/projects/1/services/a", "/projects/1/services/b"}},
		{"", nil},
	}
	for _, tc := range cases {
		got := splitAcceptedAudiences(tc.clientID)
		if len(got) != len(tc.want) {
			t.Fatalf("splitAcceptedAudiences(%q) = %v, want %v", tc.clientID, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("splitAcceptedAudiences(%q) = %v, want %v", tc.clientID, got, tc.want)
			}
		}
	}
}

func TestAssertAcceptedAudience(t *testing.T) {
	accepted := []string{
		"/projects/123456789/locations/us-west3/services/water-map",
		"/projects/123456789/locations/us-west3/services/water-models",
	}

	// aud as plain string
	if err := assertAcceptedAudience(map[string]any{
		"aud": "/projects/123456789/locations/us-west3/services/water-map",
	}, accepted); err != nil {
		t.Fatalf("expected string aud match, got %v", err)
	}

	// aud as array
	if err := assertAcceptedAudience(map[string]any{
		"aud": []any{"someone-else", "/projects/123456789/locations/us-west3/services/water-models"},
	}, accepted); err != nil {
		t.Fatalf("expected array aud match, got %v", err)
	}

	// audience for a different project must be rejected
	err := assertAcceptedAudience(map[string]any{
		"aud": "/projects/999999999/locations/us-west3/services/water-map",
	}, accepted)
	if !errors.Is(err, db.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for foreign audience, got %v", err)
	}

	// missing aud must be rejected
	if err := assertAcceptedAudience(map[string]any{}, accepted); !errors.Is(err, db.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for missing aud, got %v", err)
	}
}

func TestStringOrSliceClaim(t *testing.T) {
	if got := stringOrSliceClaim("x"); len(got) != 1 || got[0] != "x" {
		t.Fatalf("string claim: got %v", got)
	}
	if got := stringOrSliceClaim([]any{"a", "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("[]any claim: got %v", got)
	}
	if got := stringOrSliceClaim([]string{"a"}); len(got) != 1 || got[0] != "a" {
		t.Fatalf("[]string claim: got %v", got)
	}
	if got := stringOrSliceClaim(nil); got != nil {
		t.Fatalf("nil claim: got %v", got)
	}
	if got := stringOrSliceClaim(42); got != nil {
		t.Fatalf("non-string claim: got %v", got)
	}
}
