"""The one protected operation (CONTRACT.md): POST /invoke renders whatever
identity the mode's middleware attached as the contract's accept JSON. The
middleware rejects unauthenticated requests before the view runs, so a
request with neither attachment means the middleware is not installed — the
view fails closed rather than answer unauthenticated."""

from __future__ import annotations

from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_POST

from . import wire


@require_POST
def invoke(request: HttpRequest) -> JsonResponse:
    identity = getattr(request, "valiss_identity", None)
    if identity is not None:
        user = identity.user.name if identity.user is not None else None
        return JsonResponse(wire.accept(identity.account.name, user))
    claims = getattr(request, "valiss_message", None)
    if claims is not None:
        return JsonResponse(wire.accept(claims.account.name, claims.user.name))
    return JsonResponse(wire.reject("missing"), status=401)
