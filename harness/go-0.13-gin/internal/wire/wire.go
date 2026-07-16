// Package wire pins the interop entry's transport conventions: the HTTP
// route of the one protected operation, the message-mode sink audience from
// scenarios.yaml, and the contract's accept/reject response shapes
// (CONTRACT.md).
package wire

// InvokePath is the HTTP route of the harness's one protected operation;
// clients call it with POST.
const InvokePath = "/invoke"

// SinkAudience is the audience a message-mode server expects: the interop
// suite's destination identity (scenarios.yaml binds message/valid to it and
// message/wrong-audience to another).
const SinkAudience = "interop://sink"

// Accept is the contract's accept response shape.
type Accept struct {
	OK bool `json:"ok"`
	// Tenant is the account name (or key when unnamed).
	Tenant string `json:"tenant"`
	// User is the user name (or key when unnamed); null on account-level
	// requests.
	User *string `json:"user"`
}

// Reject is the contract's reject response shape; Reason is a SPEC-1.md §7
// code.
type Reject struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
}
