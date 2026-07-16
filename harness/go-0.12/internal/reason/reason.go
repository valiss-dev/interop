// Package reason reduces valiss-go's descriptive errors to the stable
// spec/SPEC-1.md §7 reason codes the interop contract asserts on rejection.
// It mirrors the substring table of valiss-go's conformance runner
// (conformance/conformance_test.go), extended with the Verifier-stage codes
// (§7.2 windows/epoch and §7.3 credential checks) that the request-level
// harness exercises and the vector-level runner does not.
package reason

import "strings"

// mapping is one §7 code and the stable fragments of the valiss-go error
// strings that reduce to it. Fragments are chosen to be mutually unambiguous
// across the table (see the conformance runner for the two near-collisions:
// "token signature:" vs "token signature verification failed", and the
// message-chain wrong-issuer string, which the more specific §7.4 code wins).
type mapping struct {
	code       string
	substrings []string
}

// table is ordered with the most specific request-stage fragments first;
// every fragment matches exactly one code, so the order is defensive, not
// load-bearing. References are to valiss-go at v0.12.0.
var table = []mapping{
	// §7.3 request / credential
	{"replay", []string{"nonce already seen"}},                                   // verifier.go:379
	{"nonce_required", []string{"request nonce required"}},                       // verifier.go:376
	{"bad_request_signature", []string{"request signature verification failed"}}, // sign.go:79
	{"bad_signature_encoding", []string{"bad request signature encoding"}},       // sign.go:71
	{"skew", []string{"skew window", "bad request timestamp"}},                   // sign.go:64-69
	{"not_bearer", []string{"request signature required"}},                       // verifier.go:367
	{"not_allowlisted", []string{"account token not recognized"}},                // verifier.go:339
	{"unknown_operator", []string{"no trusted operator"}},                        // verifier.go:310; message.go:273
	{"no_resolver", []string{"no account token resolver"}},                       // verifier.go:283
	{"operator_misconfigured", []string{"operator token misconfigured"}},         // verifier.go:276
	{"missing", []string{"missing credentials", "no token markers"}},             // verifier.go:280; creds.go:99
	{"extension_invalid", []string{"decode extension"}},                          // verifier.go:385-392

	// §7.2 token semantics
	{"epoch_mismatch", []string{"token epoch"}},  // verifier.go:329/348; message.go:334-342
	{"expired", []string{"token expired"}},       // verifier.go:323/333/351; message.go windows
	{"not_yet_valid", []string{"not yet valid"}}, // verifier.go:326/336/354
	{"wrong_type", []string{
		"not an operator token", "not an account token",
		"not a user token", "not a message token",
	}}, // token.go:356/381/406; message.go:294
	{"chain_user_mismatch", []string{"not signed by the chain's user key"}}, // message.go:324 (wins over wrong_issuer)
	{"wrong_issuer", []string{
		"not self-signed by the expected",    // operator (token.go:359)
		"not signed by the expected issuer",  // account (token.go:384)
		"not signed by the expected account", // user (token.go:409)
		"not self-signed by its user key",    // message iss != sub (message.go:297)
	}},
	{"wrong_subject_role", []string{"subject is not"}}, // token.go:362/387/412; message.go:300

	// §7.4 message-specific
	{"no_chain", []string{"carries no chain"}},                      // message.go:22/305
	{"chain_mismatch", []string{"differs from the supplied chain"}}, // message.go:309
	{"wrong_audience", []string{"message token audience"}},          // message.go:372
	{"checksum_missing", []string{"carries no checksum"}},           // message.go:377/383
	{"checksum_mismatch", []string{"payload checksum mismatch"}},    // message.go:379

	// §7.1 envelope / decode
	{"bad_signature", []string{"token signature verification failed"}},                   // token.go:251
	{"unsupported_type", []string{"unsupported token type"}},                             // token.go:201
	{"unsupported_version", []string{"unsupported wire version", "unsupported version"}}, // token.go:219; creds.go:135
	{"bad_issuer_key", []string{"token issuer:"}},                                        // token.go:243
	{"malformed", []string{
		"malformed token",  // not three parts (token.go:186)
		"token header:",    // header not base64url or not JSON (token.go:190-199)
		"token claims:",    // payload not base64url or not JSON (token.go:229-241)
		"token signature:", // signature not base64url (token.go:247-249)
		// creds envelope (creds.go between/checkVersion)
		"not closed", "unexpected content", "no content before",
	}},
}

// Code reduces a valiss-go verification error to its §7 reason code. An
// error outside the table falls back to "malformed": §7 requires every
// failure to reduce to some code, and an unmapped string is a harness bug
// best surfaced by a matrix mismatch, not a crash.
func Code(err error) string {
	msg := err.Error()
	for _, m := range table {
		for _, s := range m.substrings {
			if strings.Contains(msg, s) {
				return m.code
			}
		}
	}
	return "malformed"
}
