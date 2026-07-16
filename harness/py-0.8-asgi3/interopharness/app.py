"""The ASGI application stack enforcing the valiss scheme, the point of this
entry: valiss authentication proven through the library's *shipped* pure-ASGI
middlewares (``valiss.httpauth.asgi.Middleware`` for signed requests,
``valiss.httpsig.asgi.Middleware`` for message tokens) wrapping a minimal raw
ASGI app — no framework. The protected app never runs for an unauthenticated
request; on acceptance it renders the verified identity or message claims the
middleware stored on the request state.

The middlewares do not speak the interop contract by themselves, so a thin
adapter layer around them supplies what they cannot (each gap is this entry's
product feedback):

- Rejections: the middlewares answer with a ``text/plain`` body carrying only
  ``str(exc)`` — no §7 reason code, no rendering hook. The adapter rewrites
  those responses into the contract's ``{"ok": false, "reason": <§7>}`` JSON,
  re-deriving the code from the message via the frozen substring table in
  :mod:`.reason`, and preserving the ``valiss-chain: required`` negotiation
  header the message middleware attaches to a chainless-token rejection.
- Audience: the message middleware hardwires the verified audience to the
  request's ``host + path`` (``verify_options`` cannot override it — the
  middleware applies its own audience last). The contract binds message
  tokens to ``interop://sink``, so the adapter shims the scope the middleware
  sees: host header ``interop://sink``, path ``""``.
- Allowlist: the message middleware verifies the chain but offers no
  revocation hook, so the protected app itself holds the chain's account to
  the same allowlist the signed mode enforces.
- The signed middleware's http-extension enforcement is fail-closed and the
  fixture tokens carry none, so it runs with ``allow_missing_extension=True``.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

from valiss import MemoryReplayCache, StaticAllowlist, Verifier
from valiss import token as vtoken
from valiss.httpauth import asgi as httpauth_asgi
from valiss.httpsig import asgi as httpsig_asgi

from . import reason, wire

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def build(mode: str, operator_pub: str, allowlist: StaticAllowlist) -> ASGIApp:
    """Assemble the stack for one contract mode: the contract adapter around
    the shipped middleware around the raw protected app. In signed mode the
    verifier runs against the pinned operator key and the file-backed
    allowlist with a replay cache (signed requests must carry a nonce) and
    bearer user tokens accepted. In message mode the middleware verifies the
    per-message proof — checksum over the exact body, chain embedded or in
    the detached headers, the valiss-chain: required signal on a chainless
    token — and runs with no chain cache: a cached chain would let a later
    bare token skip negotiation, where the contract expects every chainless
    token to draw the signal."""
    if mode == "signed":
        verifier = Verifier(operator_pub, allowlist, replay_cache=MemoryReplayCache())
        stack = httpauth_asgi.Middleware(
            _signed_app, verifier=verifier, allow_missing_extension=True
        )
        return _ContractAdapter(stack, sink_shim=False)
    stack = httpsig_asgi.Middleware(_message_app(allowlist), operator_pub_key=operator_pub)
    return _ContractAdapter(stack, sink_shim=True)


async def _signed_app(scope: Scope, receive: Receive, send: Send) -> None:
    """The raw protected operation, signed mode: only ever entered with the
    middleware's verified identity on the request state."""
    identity = scope["state"][
        "valiss_identity"
    ]  # the key httpauth.asgi.Middleware stores under
    user = identity.user.name if identity.user is not None else None
    await _send_json(send, 200, wire.accept(identity.account.name, user))


def _message_app(allowlist: StaticAllowlist) -> ASGIApp:
    """The raw protected operation, message mode: the middleware has verified
    the proof and chain, and the app holds the chain's account to the
    allowlist — the revocation check the middleware has no hook for."""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        claims = scope["state"]["valiss_message"]  # httpsig.asgi.Middleware's key
        assert claims.account is not None and claims.user is not None  # chain-verified
        if claims.account.id not in allowlist:
            await _send_json(send, 401, wire.reject("not_allowlisted"))
            return
        await _send_json(send, 200, wire.accept(claims.account.name, claims.user.name))

    return app


class _ContractAdapter:
    """The adapter around a shipped middleware stack: routes the one
    operation, shims the message-mode audience, and rewrites the middleware's
    plain-text rejections into the contract JSON (see the module docstring)."""

    def __init__(self, app: ASGIApp, *, sink_shim: bool):
        self.app = app
        self.sink_shim = sink_shim

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope["path"] != wire.INVOKE_PATH:
            await _send_json(send, 404, {"ok": False, "reason": "not_found"})
            return
        if self.sink_shim:
            scope = _sink_scope(scope)
        await self.app(scope, receive, _contract_send(send))


def _sink_scope(scope: Scope) -> Scope:
    """The audience shim: the message middleware binds the verified audience
    to ``host + path`` with no override, so the scope it sees carries the
    contract's sink audience as the host and an empty path — the protected
    app behind it reads neither."""
    headers = [(k, v) for k, v in scope["headers"] if k != b"host"]
    headers.append((b"host", wire.SINK_AUDIENCE.encode("latin-1")))
    shimmed = dict(scope)
    shimmed["headers"] = headers
    shimmed["path"] = ""
    return shimmed


def _contract_send(send: Send) -> Send:
    """Wrap ``send`` to intercept a middleware rejection — a non-200 with a
    ``text/plain`` body, the middlewares' fixed rendering — buffer it, and
    replay it as the contract's 401 with the §7 code re-derived from the
    text. The valiss-chain negotiation header is carried over; the adapter's
    and protected app's own JSON responses pass through untouched. The
    middleware's 403 (extension denial) also folds to the contract's 401 —
    the contract knows only accept and reject."""
    held: dict[str, Any] = {"start": None, "body": b""}

    async def wrapped(event: dict[str, Any]) -> None:
        if event["type"] == "http.response.start":
            content_type = next(
                (v for k, v in event.get("headers") or [] if k.lower() == b"content-type"),
                b"",
            )
            if event["status"] != 200 and content_type.startswith(b"text/plain"):
                held["start"] = event
                return
            await send(event)
            return
        if held["start"] is not None and event["type"] == "http.response.body":
            held["body"] += event.get("body", b"")
            if event.get("more_body"):
                return
            text = held["body"].decode("utf-8", "replace")
            raw = json.dumps(wire.reject(reason.code(text))).encode()
            headers = [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(raw)).encode("ascii")),
            ]
            chain = next(
                (
                    v
                    for k, v in held["start"].get("headers") or []
                    if k.lower() == vtoken.HEADER_CHAIN.encode()
                ),
                None,
            )
            if chain is not None:
                headers.append((vtoken.HEADER_CHAIN.encode(), chain))
            await send({"type": "http.response.start", "status": 401, "headers": headers})
            await send({"type": "http.response.body", "body": raw})
            return
        await send(event)

    return wrapped


async def _send_json(send: Send, status: int, payload: dict[str, Any]) -> None:
    raw = json.dumps(payload).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(raw)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": raw})
