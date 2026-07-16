"""Django middleware enforcing the valiss scheme, the point of this entry:
valiss authentication proven through Django's request stack (WSGI header
access via ``request.headers``, body buffering via ``request.body``), built
on the library's public verifier API alone.

One middleware class per contract mode, both configured by the plain-data
``settings.VALISS`` dict (file paths and the mode's bindings), so either sits
in ``MIDDLEWARE`` by dotted path like any Django middleware and loads its
verification state once, at middleware construction. The protected view never
runs for an unauthenticated request; on acceptance the verified identity or
message claims ride the request object for the view to render.

Rejections short-circuit with the contract's HTTP 401 and
``{"ok": false, "reason": <§7 code>}`` (CONTRACT.md); the codes come straight
from :class:`valiss.ValissError`. A message-mode rejection for a chainless
token additionally carries the ``valiss-chain: required`` response header,
the chain-negotiation signal inviting a retransmit with the detached chain
headers.
"""

from __future__ import annotations

from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse

from valiss import MemoryReplayCache, Reason, Request, StaticAllowlist, Verifier, ValissError
from valiss import message as vmessage
from valiss import token as vtoken

from . import wire

GetResponse = Callable[[HttpRequest], HttpResponse]

# Every ValissError raised on the verification paths carries a §7 reason; an
# unmapped failure would be a harness bug best surfaced by a matrix mismatch,
# not a crash — the same fallback the py-0.8 entry uses.
_FALLBACK_REASON = "malformed"


def _reason(exc: ValissError) -> str:
    return str(exc.reason) if exc.reason is not None else _FALLBACK_REASON


def _reject(reason: str) -> JsonResponse:
    return JsonResponse(wire.reject(reason), status=401)


def _operator_pub() -> str:
    with open(settings.VALISS["OPERATOR_PUB_FILE"], encoding="utf-8") as f:
        return f.read().strip()


def _allowlist() -> StaticAllowlist:
    return StaticAllowlist.from_file(settings.VALISS["ALLOWLIST_FILE"])


class ValissSignedMiddleware:
    """Authenticates every request as a signed valiss credential: token chain
    to the pinned operator, allowlist revocation, epoch agreement, and the
    request signature over the canonical HTTP context, with replay
    suppression (the in-memory nonce cache makes a nonce mandatory on signed
    requests) and bearer user tokens accepted without a signature. The
    verified identity is attached as ``request.valiss_identity``."""

    def __init__(self, get_response: GetResponse):
        self.get_response = get_response
        self.verifier = Verifier(
            _operator_pub(), _allowlist(), replay_cache=MemoryReplayCache()
        )

    def __call__(self, request: HttpRequest) -> HttpResponse:
        headers = request.headers
        nonce = headers.get(vtoken.HEADER_NONCE) or ""
        # The raw Host header is what the client signed (SPEC-1.md §5.3);
        # request.get_host() would substitute its validated form.
        context = wire.http_request_context(
            request.method or "", headers.get("Host") or "", request.path, nonce
        )
        try:
            identity = self.verifier.verify(
                Request(
                    account_token=headers.get(vtoken.HEADER_ACCOUNT_TOKEN) or "",
                    user_token=headers.get(vtoken.HEADER_USER_TOKEN) or "",
                    timestamp=headers.get(vtoken.HEADER_TIMESTAMP) or "",
                    signature=headers.get(vtoken.HEADER_SIGNATURE) or "",
                    context=context,
                    nonce=nonce,
                )
            )
        except ValissError as exc:
            return _reject(_reason(exc))
        request.valiss_identity = identity  # type: ignore[attr-defined]
        return self.get_response(request)


class ValissMessageMiddleware:
    """Verifies a per-message proof of origin over the exact request body:
    audience pinned to the configured sink, checksum bound to the received
    bytes, the provenance chain either embedded in the token or taken from
    the detached ``valiss-chain-account-token``/``valiss-chain-user-token``
    headers, and the chain's account held to the same allowlist the signed
    mode enforces. A token with no chain at all is rejected ``no_chain`` and
    the response carries ``valiss-chain: required``. The verified claims are
    attached as ``request.valiss_message``."""

    def __init__(self, get_response: GetResponse):
        self.get_response = get_response
        self.operator_pub = _operator_pub()
        self.allowlist = _allowlist()
        self.audience = settings.VALISS["AUDIENCE"]

    def __call__(self, request: HttpRequest) -> HttpResponse:
        headers = request.headers
        token = headers.get(vtoken.HEADER_MESSAGE_TOKEN) or ""
        if not token:
            return _reject("missing")
        # Detached chain delivery: the chain is supplied out of band only when
        # both headers are present (a half chain binds nothing), letting
        # verify_message settle the reason for whatever the token carries.
        chain_account = headers.get(vtoken.HEADER_CHAIN_ACCOUNT_TOKEN) or ""
        chain_user = headers.get(vtoken.HEADER_CHAIN_USER_TOKEN) or ""
        detached = (chain_account, chain_user) if chain_account and chain_user else None
        try:
            # request.body buffers the payload; the view can still read it.
            claims = vmessage.verify_message(
                token,
                self.operator_pub,
                audience=self.audience,
                payload=request.body,
                chain=detached,
            )
        except ValissError as exc:
            response = _reject(_reason(exc))
            if exc.reason == Reason.NO_CHAIN:
                # The chain-negotiation signal: the client may retransmit once
                # with the detached chain headers (CONTRACT.md).
                response[vtoken.HEADER_CHAIN] = vtoken.CHAIN_REQUIRED
            return response
        assert claims.account is not None and claims.user is not None  # chain-verified
        if claims.account.id not in self.allowlist:
            return _reject("not_allowlisted")
        request.valiss_message = claims  # type: ignore[attr-defined]
        return self.get_response(request)
