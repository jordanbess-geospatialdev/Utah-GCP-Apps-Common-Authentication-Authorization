package authz_test

import (
	"testing"
	"time"

	"github.com/utah-dnr/utah-gcp-common-authz/internal/authz"
	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
)

func TestEvaluateConditions(t *testing.T) {
	noonUTC := time.Date(2026, 10, 22, 14, 0, 0, 0, time.UTC)
	lateUTC := time.Date(2026, 10, 22, 23, 0, 0, 0, time.UTC)

	cond := domain.ABACConditions{
		RequireMFA:         true,
		IPCIDRs:            []string{"204.113.0.0/16", "10.10.0.0/24"},
		AllowedUserTypes:   []string{"state_employee"},
		RequiredAttributes: map[string]string{"division": "DWRe"},
		AllowedHoursUTC:    &domain.TimeWindowUTC{StartHour: 12, EndHour: 20},
	}

	// 1. All conditions satisfied
	ok, reason := authz.EvaluateConditions(cond, domain.RequestContext{
		ClientIP:      "204.113.55.12",
		MFAVerified:   true,
		UserType:      "state_employee",
		Attributes:    map[string]string{"division": "DWRe"},
		EvaluationUTC: &noonUTC,
	})
	if !ok {
		t.Fatalf("expected conditions to pass, failed with: %s", reason)
	}

	// 2. Outside UTC window
	ok, reason = authz.EvaluateConditions(cond, domain.RequestContext{
		ClientIP:      "204.113.55.12",
		MFAVerified:   true,
		UserType:      "state_employee",
		Attributes:    map[string]string{"division": "DWRe"},
		EvaluationUTC: &lateUTC,
	})
	if ok || reason != "outside_allowed_utc_hours" {
		t.Fatalf("expected outside_allowed_utc_hours, got ok=%v reason=%s", ok, reason)
	}

	// 3. Missing required attribute
	ok, reason = authz.EvaluateConditions(cond, domain.RequestContext{
		ClientIP:      "204.113.55.12",
		MFAVerified:   true,
		UserType:      "state_employee",
		Attributes:    map[string]string{"division": "DOGM"},
		EvaluationUTC: &noonUTC,
	})
	if ok || reason != "missing_required_attribute_division" {
		t.Fatalf("expected missing_required_attribute_division, got ok=%v reason=%s", ok, reason)
	}
}
