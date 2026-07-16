"""The entry's middleware: the shipped valiss-py Django middleware bindings
(the enforcement path this entry exists to exercise, bound at the bottom of
this module) plus the contract glue around them (CONTRACT.md).

Enforcement is ``valiss.httpauth.django`` in signed mode and
``valiss.httpsig.django`` in message mode; the glue layers only what the
interop contract demands and the shipped classes do not produce, mirroring
the gin entry's adapter/glue split. Per item:

- ``contract_responses`` (bypass — the adapter cannot express it): the
  shipped middleware renders every rejection as a plain-text body built from
  the ValissError's message and discards the exception's §7 ``reason``, with
  no hook over the response shape, so an outer middleware rewrites non-JSON
  error responses into the contract's ``{"ok": false, "reason": <§7>}`` JSON,
  recovering the code from the text (:mod:`.reason`). Headers pass through
  untouched — including the ``valiss-chain: required`` negotiation signal the
  shipped message middleware stamps natively on chainless tokens, which is
  therefore not reimplemented here.
- ``sink_audience`` (bypass — the adapter cannot express it): the shipped
  message receiver pins the expected audience to the transport address (Host
  header plus path, ``valiss.httpsig._core.audience``) with no override,
  while the suite binds tokens to the logical audience ``interop://sink``.
  Rewriting the audience-bearing request fields before the shipped middleware
  runs makes its own derivation yield the suite's audience — the same trick
  the gin/echo entries play on the request URL.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse

from valiss import MemoryReplayCache, StaticAllowlist, Verifier
from valiss.httpauth import django as httpauth_django
from valiss.httpsig import django as httpsig_django

from . import reason, wire

GetResponse = Callable[[HttpRequest], HttpResponse]


def contract_responses(get_response: GetResponse) -> GetResponse:
    """Rewrite the shipped middleware's plain-text rejections into the
    contract's reject JSON, keeping the status and every header. JSON
    responses (the view's own accept and reject shapes) pass through
    untouched."""

    def process(request: HttpRequest) -> HttpResponse:
        response = get_response(request)
        content_type = response.get("Content-Type") or ""
        if response.status_code != 200 and not content_type.startswith("application/json"):
            body = response.content.decode("utf-8", "replace")
            response.content = json.dumps(wire.reject(reason.code(body))).encode()
            response["Content-Type"] = "application/json"
        return response

    return process


def sink_audience(get_response: GetResponse) -> GetResponse:
    """Make the shipped message receiver expect the interop suite's logical
    audience by rewriting the fields it derives the audience from: the Host
    header becomes ``interop://sink`` and the path contributes nothing.

    Safe because this runs before anything materializes ``request.headers``
    (a cached property over META), URL routing resolves on the untouched
    ``request.path_info``, and nothing downstream reads the original Host or
    ``request.path`` (``get_host()`` is never called; ``ALLOWED_HOSTS`` is
    ``["*"]`` regardless)."""

    def process(request: HttpRequest) -> HttpResponse:
        request.META["HTTP_HOST"] = wire.SINK_AUDIENCE
        request.path = ""
        return get_response(request)

    return process

# --- Shipped valiss middleware bindings -------------------------------------
# The enforcement path this entry exists to exercise: each shipped factory
# (``valiss.httpauth.django.middleware``, ``valiss.httpsig.django.middleware``)
# returns a closure over verification state, built once here and referenced
# from ``MIDDLEWARE`` by dotted path. Signed mode: pinned operator key,
# file-backed allowlist (revocation), in-memory replay cache (nonce
# mandatory), bearer accepted, and the adapter's own allow_missing_extension
# relaxation (fixture tokens carry no http extension). Message mode: the
# shipped receiver, which natively answers chainless tokens with the
# ``valiss-chain: required`` signal; no chain_cache, or a bare token would
# reuse a previously negotiated chain and break bare-signals-negotiation.
# Chain revocation is the receiver's job by design, so the view performs the
# allowlist check on the chain account, reading ``allowlist`` from here.


def _operator_pub() -> str:
    with open(settings.VALISS["OPERATOR_PUB_FILE"], encoding="utf-8") as f:
        return f.read().strip()


_operator_pub_key = _operator_pub()

# The revocation state both modes enforce: the signed Verifier holds it
# internally; message mode reads it from the view.
allowlist = StaticAllowlist.from_file(settings.VALISS["ALLOWLIST_FILE"])

valiss_signed = httpauth_django.middleware(
    Verifier(_operator_pub_key, allowlist, replay_cache=MemoryReplayCache()),
    allow_missing_extension=True,
)

valiss_message = httpsig_django.middleware(_operator_pub_key)
