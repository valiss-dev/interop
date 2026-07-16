"""The interop entry's transport conventions, the HTTP subset of the py-0.8
entry's ``wire.py``: the route of the one protected operation, the canonical
request-context bytes of SPEC-1.md §5.3 (reconstructed here so the entry's
parity with the reference entries is plain), the message-mode sink audience
from scenarios.yaml, and the contract's accept/reject response shapes
(CONTRACT.md).

The context byte layout is identical to valiss-py's
``valiss.httpauth.extension.request_context``; it is restated here so the
harness's wire conventions live in one visible place.
"""

from __future__ import annotations

from typing import Any

# INVOKE_PATH is the HTTP route of the harness's one protected operation;
# clients call it with POST.
INVOKE_PATH = "/invoke"

# SINK_AUDIENCE is the audience a message-mode server expects: the interop
# suite's destination identity (scenarios.yaml binds message/valid to it and
# message/wrong-audience to another).
SINK_AUDIENCE = "interop://sink"


def http_request_context(method: str, host: str, path: str, nonce: str) -> bytes:
    """The SPEC-1.md §5.3 canonical context for an HTTP request: method, host,
    and path exactly, query excluded, with the per-request nonce (empty when
    replay suppression is not in use)."""
    return f"http\n{method}\n{host}\n{path}\n{nonce}".encode()


def accept(tenant: str, user: str | None) -> dict[str, Any]:
    """The contract's accept response shape: tenant is the account name (or
    key when unnamed), user the user name (or key), null on account-level
    requests."""
    return {"ok": True, "tenant": tenant, "user": user}


def reject(reason: str) -> dict[str, Any]:
    """The contract's reject response shape; reason is a SPEC-1.md §7 code."""
    return {"ok": False, "reason": reason}
