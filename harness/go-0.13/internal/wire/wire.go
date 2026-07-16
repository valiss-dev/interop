// Package wire pins the interop entry's transport conventions: the HTTP
// route of the one protected operation, the canonical request-context bytes
// of SPEC-1.md §5.3 (reconstructed here because the client must be able to
// sign with a caller-fixed nonce, and with whatever seed the creds supply),
// the message-mode sink audience from scenarios.yaml, and the contract's
// accept/reject response shapes (CONTRACT.md).
package wire

// InvokePath is the HTTP route of the harness's one protected operation;
// clients call it with POST.
const InvokePath = "/invoke"

// SinkAudience is the audience a message-mode server expects: the interop
// suite's destination identity (scenarios.yaml binds message/valid to it and
// message/wrong-audience to another).
const SinkAudience = "interop://sink"

// HTTPRequestContext renders the SPEC-1.md §5.3 canonical context for an
// HTTP request: method, host, and path exactly, query excluded, with the
// per-request nonce (empty when replay suppression is not in use).
func HTTPRequestContext(method, host, path, nonce string) []byte {
	return []byte("http\n" + method + "\n" + host + "\n" + path + "\n" + nonce)
}

// GRPCRequestContext renders the SPEC-1.md §5.3 canonical context for a gRPC
// call: the full method with the per-request nonce.
func GRPCRequestContext(fullMethod, nonce string) []byte {
	return []byte("grpc\n" + fullMethod + "\n" + nonce)
}

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

// Response parses either shape, for the client side.
type Response struct {
	OK     bool    `json:"ok"`
	Tenant string  `json:"tenant"`
	User   *string `json:"user"`
	Reason string  `json:"reason"`
}
