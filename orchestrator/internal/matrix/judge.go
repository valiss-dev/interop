package matrix

import (
	"errors"
	"fmt"
	"strings"

	"github.com/valiss-dev/interop/orchestrator/internal/runner"
	"github.com/valiss-dev/interop/orchestrator/internal/suite"
)

// isAccept reports the transport's accept status: HTTP 200 / gRPC OK.
// JSON numbers decode into float64, hence the type switch.
func isAccept(transport string, status any) bool {
	switch transport {
	case suite.TransportHTTP:
		n, ok := status.(float64)
		return ok && n == 200
	case suite.TransportGRPC:
		s, ok := status.(string)
		return ok && s == "OK"
	}
	return false
}

// isReject reports the transport's reject status: HTTP 401 / gRPC
// UNAUTHENTICATED. Anything else is neither accept nor reject and fails the
// scenario either way.
func isReject(transport string, status any) bool {
	switch transport {
	case suite.TransportHTTP:
		n, ok := status.(float64)
		return ok && n == 401
	case suite.TransportGRPC:
		s, ok := status.(string)
		return ok && s == "UNAUTHENTICATED"
	}
	return false
}

// judgeWarmup asserts a pre-final repeat attempt, which must be accepted.
func judgeWarmup(transport string, out runner.Outcome) error {
	if !isAccept(transport, out.Status) {
		return fmt.Errorf("expected accept, got %s", fmtOutcome(out))
	}
	return nil
}

// judgeFinal compares the client-reported outcome to the scenario
// expectation. Tenant and user are asserted only when the expectation names
// them; a reject must carry the exact §7 reason and no identity.
func judgeFinal(transport string, want *suite.Expect, out runner.Outcome) error {
	if want.Accept {
		if !isAccept(transport, out.Status) {
			return fmt.Errorf("expected accept, got %s", fmtOutcome(out))
		}
		if out.Reason != nil {
			return fmt.Errorf("accept carried reason %q", *out.Reason)
		}
		if out.Identity == nil {
			return errors.New("accept carried no identity")
		}
		if want.Tenant != nil && out.Identity.Tenant != *want.Tenant {
			return fmt.Errorf("tenant = %q, want %q", out.Identity.Tenant, *want.Tenant)
		}
		if want.User != nil {
			if out.Identity.User == nil {
				return fmt.Errorf("user = null, want %q", *want.User)
			}
			if *out.Identity.User != *want.User {
				return fmt.Errorf("user = %q, want %q", *out.Identity.User, *want.User)
			}
		}
		return nil
	}
	if !isReject(transport, out.Status) {
		return fmt.Errorf("expected reject with reason %q, got %s", want.Reason, fmtOutcome(out))
	}
	if out.Reason == nil {
		return fmt.Errorf("reject carried no reason, want %q", want.Reason)
	}
	if *out.Reason != want.Reason {
		return fmt.Errorf("reason = %q, want %q", *out.Reason, want.Reason)
	}
	if out.Identity != nil {
		return fmt.Errorf("reject carried identity %s", fmtIdentity(out.Identity))
	}
	return nil
}

func fmtOutcome(out runner.Outcome) string {
	var b strings.Builder
	fmt.Fprintf(&b, "status=%v", out.Status)
	if out.Reason != nil {
		fmt.Fprintf(&b, " reason=%q", *out.Reason)
	}
	if out.Identity != nil {
		fmt.Fprintf(&b, " identity=%s", fmtIdentity(out.Identity))
	}
	return b.String()
}

func fmtIdentity(id *runner.Identity) string {
	user := "null"
	if id.User != nil {
		user = fmt.Sprintf("%q", *id.User)
	}
	return fmt.Sprintf("{tenant:%q user:%s}", id.Tenant, user)
}
