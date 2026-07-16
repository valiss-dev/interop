"""The interop entry's transport conventions, the HTTP subset of the py-0.8
entry's ``wire.py``: the route of the one protected operation, the
message-mode sink audience from scenarios.yaml, and the contract's
accept/reject response shapes (CONTRACT.md). The canonical request-context
bytes are not restated here: this entry's point is that the shipped ASGI
middleware derives them itself (``valiss.httpauth.extension.request_context``).
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


def accept(tenant: str, user: str | None) -> dict[str, Any]:
    """The contract's accept response shape: tenant is the account name (or
    key when unnamed), user the user name (or key), null on account-level
    requests."""
    return {"ok": True, "tenant": tenant, "user": user}


def reject(reason: str) -> dict[str, Any]:
    """The contract's reject response shape; reason is a SPEC-1.md §7 code."""
    return {"ok": False, "reason": reason}
