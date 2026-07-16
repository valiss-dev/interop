"""Reduce the shipped ASGI middlewares' rejection text to the stable
spec/SPEC-1.md §7 reason codes the interop contract asserts on rejection.

valiss-py carries first-class reason codes (``ValissError.reason``), but the
ASGI middlewares render rejections as ``str(exc)`` — the human-readable
message the library documents as illustrative — and expose neither the code
nor a rendering hook to the wrapping application. So this entry re-derives
the code from the message the way the Go framework-adapter entries do against
raw Go errors (their ``internal/reason`` substring tables). The fragments
below are the valiss-py texts frozen by this entry's exact ``valiss==0.8.0``
pin, plus the fixed strings the middlewares render themselves (the
missing-token and chain-required rejections).
"""

from __future__ import annotations

# The table pairs one §7 code with the stable fragments of the valiss-py
# error strings that reduce to it. It is ordered with the most specific
# request-stage fragments first; every fragment matches exactly one code, so
# the order is defensive, not load-bearing. References are to valiss-py at
# v0.8.0.
_TABLE: list[tuple[str, list[str]]] = [
    # §7.3 request / credential
    ("replay", ["nonce already seen"]),                                   # verifier.py
    ("nonce_required", ["request nonce required"]),                       # verifier.py
    ("bad_request_signature", [
        "request signature verification failed",                          # token.py verify_signature
        "bad subject public key",                                         # token.py verify_signature
    ]),
    ("bad_signature_encoding", ["bad request signature encoding"]),       # token.py verify_signature
    ("skew", ["skew window", "bad request timestamp"]),                   # token.py verify_signature
    ("not_bearer", ["request signature required"]),                       # verifier.py
    ("not_allowlisted", ["account token not recognized"]),                # verifier.py
    ("unknown_operator", ["no trusted operator"]),                        # verifier.py; message.py
    ("no_resolver", ["no account token resolver"]),                       # verifier.py
    ("operator_misconfigured", ["operator token misconfigured"]),         # verifier.py
    ("validator_rejected", ["validator rejected"]),                       # verifier.py
    ("missing", [
        "missing credentials",                                            # httpauth._server / verifier.py
        "missing message token",                                          # httpsig.asgi middleware
    ]),
    ("extension_invalid", [
        "decode extension",                                               # token.py ext_of
        "no http extension",                                              # httpauth.extension authorize_ext
        "does not permit",                                                # httpauth.extension authorize_ext
    ]),

    # §7.2 token semantics
    ("epoch_mismatch", ["token epoch"]),                                  # verifier.py; message.py
    ("expired", ["token expired"]),                                       # verifier.py; message.py windows
    ("not_yet_valid", ["not yet valid"]),                                 # verifier.py; message.py windows
    ("wrong_type", [
        "not an operator token", "not an account token",
        "not a user token", "not a message token",
    ]),                                                                   # token.py; message.py
    ("chain_user_mismatch", ["not signed by the chain's user key"]),      # message.py (wins over wrong_issuer)
    ("wrong_issuer", [
        "not self-signed by the expected",                                # operator (token.py)
        "not signed by the expected issuer",                              # account (token.py)
        "not signed by the expected account",                             # user (token.py)
        "not self-signed by its user key",                                # message iss != sub (message.py)
    ]),
    ("wrong_subject_role", ["subject is not"]),                           # token.py; message.py

    # §7.4 message-specific. The httpsig middleware answers a chainless
    # token with its own fixed "message token chain required" text instead
    # of the library's "carries no chain" error, so both fragments reduce
    # to no_chain.
    ("no_chain", ["carries no chain", "message token chain required"]),   # message.py; _msgtransport.py
    ("chain_mismatch", ["differs from the supplied chain"]),              # message.py
    ("wrong_audience", ["message token audience"]),                       # message.py
    ("checksum_missing", ["carries no checksum"]),                        # message.py
    ("checksum_mismatch", ["payload checksum mismatch"]),                 # message.py

    # §7.1 envelope / decode
    ("bad_signature", ["token signature verification failed"]),           # token.py _decode_v1
    ("unsupported_type", ["unsupported token type"]),                     # token.py _peek_version
    ("unsupported_version", ["unsupported wire version"]),                # token.py _decode_token
    ("bad_issuer_key", ["token issuer:"]),                                # token.py _decode_v1
    ("malformed", [
        "malformed token",                                                # not three parts / header version
        "token header:",                                                  # header not base64url / not JSON
        "token claims:",                                                  # payload not base64url / wrong shapes
    ]),
]


def code(message: str) -> str:
    """Reduce a middleware rejection's text to its §7 reason code. Text
    outside the table falls back to "malformed": §7 requires every failure to
    reduce to some code, and an unmapped string is a harness bug best
    surfaced by a matrix mismatch, not a crash."""
    for reason_code, fragments in _TABLE:
        for fragment in fragments:
            if fragment in message:
                return reason_code
    return "malformed"
