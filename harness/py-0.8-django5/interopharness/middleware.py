"""Contract glue around the shipped valiss-py Django middleware (CONTRACT.md).

Enforcement is the shipped middleware bound in :mod:`.auth`
(``valiss.httpauth.django`` in signed mode, ``valiss.httpsig.django`` in
message mode); this module layers only what the interop contract demands and
the shipped classes do not produce, mirroring the gin entry's adapter/glue
split. Per item:

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

from django.http import HttpRequest, HttpResponse

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
