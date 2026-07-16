"""The one protected operation (CONTRACT.md): POST /invoke renders whatever
the shipped valiss middleware attached — read through the library's own
accessors — as the contract's accept JSON. The middleware rejects
unauthenticated requests before the view runs, so a request with neither
attachment means no valiss middleware is installed: the view fails closed
rather than answer unauthenticated.

In message mode the view also holds the chain's account to the same
allowlist signed mode enforces. Message verification itself is offline and
the library leaves revocation to the receiver, so this check is the
documented integration point (the same placement as the gin entry's
handler), not a bypass of adapter code.
"""

from __future__ import annotations

from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_POST

from valiss import Reason
from valiss.httpauth.django import identity
from valiss.httpsig.django import message_claims

from . import auth, wire


@require_POST
def invoke(request: HttpRequest) -> JsonResponse:
    ident = identity(request)
    if ident is not None:
        user = ident.user.name if ident.user is not None else None
        return JsonResponse(wire.accept(ident.account.name, user))
    claims = message_claims(request)
    if claims is not None:
        assert claims.account is not None and claims.user is not None  # chain-verified
        if claims.account.id not in auth.allowlist:
            # A Reason member is its wire string (StrEnum), so the code rides
            # straight from the library's taxonomy into the reject JSON.
            return JsonResponse(wire.reject(Reason.NOT_ALLOWLISTED), status=401)
        return JsonResponse(wire.accept(claims.account.name, claims.user.name))
    return JsonResponse(wire.reject(Reason.MISSING), status=401)
