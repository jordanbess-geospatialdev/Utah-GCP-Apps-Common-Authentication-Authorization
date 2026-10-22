package authz

import (
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/utah-dnr/utah-gcp-common-authz/internal/domain"
)

// EvaluateConditions checks whether all Zero Trust ABAC conditions on a role assignment or permission
// are satisfied by the runtime RequestContext.
func EvaluateConditions(cond domain.ABACConditions, reqCtx domain.RequestContext) (bool, string) {
	// 1. Multi-Factor Authentication check
	if cond.RequireMFA && !reqCtx.MFAVerified {
		return false, "mfa_required"
	}

	// 2. Client IP CIDR boundary check
	if len(cond.IPCIDRs) > 0 {
		if reqCtx.ClientIP == "" {
			return false, "client_ip_missing_for_cidr_policy"
		}
		clientIP := net.ParseIP(reqCtx.ClientIP)
		if clientIP == nil {
			return false, "invalid_client_ip"
		}
		matchedCIDR := false
		for _, cidrStr := range cond.IPCIDRs {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err == nil && ipNet.Contains(clientIP) {
				matchedCIDR = true
				break
			}
		}
		if !matchedCIDR {
			return false, "client_ip_outside_allowed_cidrs"
		}
	}

	// 3. Allowed User Types check (e.g., restricting a role to 'state_employee' only)
	if len(cond.AllowedUserTypes) > 0 {
		if !slices.Contains(cond.AllowedUserTypes, reqCtx.UserType) {
			return false, fmt.Sprintf("user_type_%s_not_allowed", reqCtx.UserType)
		}
	}

	// 4. Required User/Context Attributes check (e.g., {"agency": "DNR", "clearance": "hydro_level_2"})
	if len(cond.RequiredAttributes) > 0 {
		for k, expectedVal := range cond.RequiredAttributes {
			actualVal, ok := reqCtx.Attributes[k]
			if !ok || actualVal != expectedVal {
				return false, fmt.Sprintf("missing_required_attribute_%s", k)
			}
		}
	}

	// 5. UTC Time Window check
	if cond.AllowedHoursUTC != nil {
		evalTime := time.Now().UTC()
		if reqCtx.EvaluationUTC != nil {
			evalTime = reqCtx.EvaluationUTC.UTC()
		}
		hr := evalTime.Hour()
		start := cond.AllowedHoursUTC.StartHour
		end := cond.AllowedHoursUTC.EndHour

		inWindow := false
		if start <= end {
			inWindow = hr >= start && hr <= end
		} else {
			// Overnight window wrapping midnight UTC (e.g., 22 to 06)
			inWindow = hr >= start || hr <= end
		}
		if !inWindow {
			return false, "outside_allowed_utc_hours"
		}
	}

	return true, ""
}
