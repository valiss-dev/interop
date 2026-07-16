"""The interop entry's transport conventions, mirroring the reference entry's
``go-0.12/internal/wire``: the HTTP route of the one protected operation, the
canonical request-context bytes of SPEC-1.md §5.3 (reconstructed here because
the client must sign with a caller-fixed nonce, and with whatever seed the
creds supply), the message-mode sink audience from scenarios.yaml, and the
contract's accept/reject response shapes (CONTRACT.md).

The context byte layouts are identical to valiss-py's contrib transports
(``valiss.httpauth.extension.request_context`` and
``valiss.grpcauth.extension.method_context``); they are restated here so the
harness carries no framework dependency and its parity with go-0.12 is plain.
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

# GRPC_FULL_METHOD is the one protected gRPC operation, from
# interoppb/interop.proto (the go-0.12 entry defines the service).
GRPC_FULL_METHOD = "/valiss.interop.v1.Interop/Invoke"


def http_request_context(method: str, host: str, path: str, nonce: str) -> bytes:
    """The SPEC-1.md §5.3 canonical context for an HTTP request: method, host,
    and path exactly, query excluded, with the per-request nonce (empty when
    replay suppression is not in use)."""
    return f"http\n{method}\n{host}\n{path}\n{nonce}".encode()


def grpc_request_context(full_method: str, nonce: str) -> bytes:
    """The SPEC-1.md §5.3 canonical context for a gRPC call: the full method
    with the per-request nonce."""
    return f"grpc\n{full_method}\n{nonce}".encode()


def accept(tenant: str, user: str | None) -> dict[str, Any]:
    """The contract's accept response shape: tenant is the account name (or
    key when unnamed), user the user name (or key), null on account-level
    requests."""
    return {"ok": True, "tenant": tenant, "user": user}


def reject(reason: str) -> dict[str, Any]:
    """The contract's reject response shape; reason is a SPEC-1.md §7 code."""
    return {"ok": False, "reason": reason}
