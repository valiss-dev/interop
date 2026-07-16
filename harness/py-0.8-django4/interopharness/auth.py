"""The shipped valiss-py Django middleware, bound the way its docstrings
prescribe: each factory (``valiss.httpauth.django.middleware``,
``valiss.httpsig.django.middleware``) returns a closure over its verification
state, built once in a small module and referenced from ``MIDDLEWARE`` by
dotted path. The entry exists to exercise these shipped classes, so this
module is the enforcement path; the contract glue around them lives in
:mod:`.middleware` and :mod:`.views`.

``valiss_signed`` — signed-request mode: the shipped Verifier holds the
pinned operator key, the file-backed allowlist (revocation), and an
in-memory replay cache (which makes a nonce mandatory on signed requests);
bearer user tokens are accepted without a signature. The fixture tokens
carry no http extension and the interop contract has no extension
dimension, so the fail-closed default is relaxed with the adapter's own
``allow_missing_extension`` option — the same relaxation the gin entry
applies with ``httpauth.AllowMissingExtension()``.

``valiss_message`` — message-token mode: the shipped receiver verifies the
per-message proof against the operator key (chain, audience, checksum,
validity windows, epoch agreement) and natively answers a chainless token
with the ``valiss-chain: required`` negotiation signal. No ``chain_cache``
is configured: a cache would let a bare token reuse a chain negotiated by
an earlier request, and the suite's bare-signals-negotiation scenario
asserts the no_chain rejection. The library leaves chain revocation to the
receiver, so the allowlist check on the chain's account lives in the view
(:mod:`.views`), which reads this module's ``allowlist``.
"""

from __future__ import annotations

from django.conf import settings

from valiss import MemoryReplayCache, StaticAllowlist, Verifier
from valiss.httpauth import django as httpauth_django
from valiss.httpsig import django as httpsig_django


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
