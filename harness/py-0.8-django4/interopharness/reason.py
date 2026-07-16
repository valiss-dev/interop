"""Reduce valiss-py's descriptive rejection text to the stable spec/SPEC-1.md
§7 reason codes the interop contract asserts on rejection (CONTRACT.md).

The shipped Django middleware renders a rejection as the ValissError's
message text and drops the exception's ``reason`` attribute on the floor
(``valiss.httpauth._server.authenticate`` reduces to ``(status, str(exc))``,
``valiss._msgtransport.Reject`` carries only the message), so the harness
recovers the §7 code from the text — the same reduction the gin/echo entries
perform on valiss-go's adapter output, keyed to valiss-py's strings (which
mirror the Go implementation's message for message). Fragments are chosen to
be mutually unambiguous across the table; references are to valiss-py at
v0.8.0.
"""

from __future__ import annotations

# One §7 code and the stable fragments of the valiss-py error strings that
# reduce to it. Ordered with the most specific request-stage fragments first;
# every fragment matches exactly one code, so the order is defensive, not
# load-bearing.
_TABLE: tuple[tuple[str, tuple[str, ...]], ...] = (
    # §7.3 request / credential
    ("replay", ("nonce already seen",)),  # verifier.py:332
    ("nonce_required", ("request nonce required",)),  # verifier.py:329
    ("bad_request_signature", (
        "request signature verification failed",  # token.py:821
        "bad subject public key",  # token.py:812
    )),
    ("bad_signature_encoding", ("bad request signature encoding",)),  # token.py:806
    ("skew", ("skew window", "bad request timestamp")),  # token.py:792-800
    ("not_bearer", ("request signature required",)),  # verifier.py:320
    ("not_allowlisted", ("account token not recognized",)),  # verifier.py:296
    ("unknown_operator", ("no trusted operator",)),  # verifier.py:369; message.py:228
    ("no_resolver", ("no account token resolver",)),  # verifier.py:266
    ("operator_misconfigured", ("operator token misconfigured",)),  # verifier.py:257
    ("missing", (
        "missing credentials",  # httpauth/_server.py:30; verifier.py:264
        "missing message token",  # httpsig/django.py:54
    )),
    ("extension_invalid", (
        "decode extension",  # token.py:220
        "no http extension",  # httpauth/extension.py:105
        "does not permit",  # httpauth/extension.py:109
    )),

    # §7.2 token semantics
    ("epoch_mismatch", ("token epoch",)),  # verifier.py:287/303; message.py:258-268
    ("expired", ("token expired",)),  # verifier.py:280/292/307; message.py windows
    ("not_yet_valid", ("not yet valid",)),  # verifier.py:284/294/309; message.py windows
    ("wrong_type", (
        "not an operator token", "not an account token",
        "not a user token", "not a message token",
    )),  # token.py:665/687/708; message.py:178
    # message.py:245 — listed before wrong_issuer so the more specific §7.4
    # chain code wins over the "not signed by the ..." family.
    ("chain_user_mismatch", ("not signed by the chain's user key",)),
    ("wrong_issuer", (
        "not self-signed by the expected operator",  # token.py:668
        "not signed by the expected issuer",  # token.py:690
        "not signed by the expected account",  # token.py:711
        "not self-signed by its user key",  # message.py:181
    )),
    ("wrong_subject_role", ("subject is not",)),  # token.py:673/694/715; message.py:185

    # §7.4 message-specific. The shipped receiver answers a chainless token
    # with its own fixed "message token chain required" text
    # (_msgtransport.py:157) instead of verify_message's "carries no chain"
    # error, so both fragments reduce to no_chain.
    ("no_chain", ("carries no chain", "message token chain required")),  # message.py:193
    ("chain_mismatch", ("differs from the supplied chain",)),  # message.py:202
    ("wrong_audience", ("message token audience",)),  # message.py:299
    ("checksum_missing", ("carries no checksum",)),  # message.py:305/309
    ("checksum_mismatch", ("payload checksum mismatch",)),  # message.py:307

    # §7.1 envelope / decode
    ("bad_signature", ("token signature verification failed",)),  # token.py:556
    ("unsupported_type", ("unsupported token type",)),  # token.py:510
    ("unsupported_version", ("unsupported wire version",)),  # token.py:531
    ("bad_issuer_key", ("token issuer:",)),  # token.py:550
    ("malformed", (
        "malformed token",  # token.py:116/501/518 (also the header-version text)
        "token header:",  # token.py:505/507
        "token claims:",  # token.py:543-613
    )),
)

_FALLBACK = "malformed"


def code(text: str) -> str:
    """Reduce valiss-py rejection text to its §7 reason code. Text outside the
    table falls back to "malformed": §7 requires every failure to reduce to
    some code, and an unmapped string is a harness bug best surfaced by a
    matrix mismatch, not a crash."""
    for reason_code, fragments in _TABLE:
        for fragment in fragments:
            if fragment in text:
                return reason_code
    return _FALLBACK
