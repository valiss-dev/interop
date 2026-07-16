"""The Django interop harness server for the valiss-py 0.8 series
(CONTRACT.md): it exposes exactly one protected operation over HTTP — a
minimal Django project enforced by the shipped Django middleware of
valiss-py 0.8 (``valiss.httpauth.django`` for signed mode,
``valiss.httpsig.django`` for message mode; bound in :mod:`.middleware`). The
entry exists to exercise the shipped middleware, so it is the enforcement
path; the harness only layers the contract glue the shipped classes do not
produce (:mod:`.middleware`, :mod:`.views`).

In signed mode the shipped Verifier checks the chain against the pinned
operator key, the file-backed allowlist, epoch agreement, and the request
signature, with a replay cache (signed requests must carry a nonce) and
bearer user tokens accepted. In message mode the shipped receiver verifies a
per-message proof of origin — audience (rewritten to the interop sink by the
glue), checksum over the received payload, the chain embedded or in the
detached headers — and answers a chainless token with the ``valiss-chain:
required`` negotiation signal; the view holds the chain's account to the
same allowlist.

Accept answers HTTP 200 with the contract's accept JSON; reject answers HTTP
401 with {"ok":false,"reason":<§7>}. The Django WSGI application runs under
a threaded wsgiref server — the same stdlib machinery Django's own runserver
wraps — because it is single-process (one MemoryReplayCache sees every
nonce, where a pre-forking server would shard the cache across workers) and
dependency-free. It prints "ready <addr>" once listening and exits cleanly
on SIGTERM.
"""

from __future__ import annotations

import argparse
import secrets
import signal
import socketserver
import sys
import threading
from typing import Any, NoReturn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import django
from django.conf import settings
from django.core.wsgi import get_wsgi_application

from valiss import ValissError


def configure(mode: str, operator: str, allowlist: str) -> None:
    """Assemble the minimal Django project: the contract glue outermost, the
    mode's shipped valiss middleware innermost, one route, and no apps,
    database, or templates. SECRET_KEY is random per process — no Django
    signing feature is in play, the setting only has to be non-empty."""
    middleware = [f"{__package__}.middleware.contract_responses"]
    if mode == "message":
        # The audience rewrite must precede the shipped middleware (and any
        # request.headers access); signed mode signs the real host and path,
        # so it must not see the rewrite.
        middleware.append(f"{__package__}.middleware.sink_audience")
    middleware.append(
        f"{__package__}.middleware.valiss_signed"
        if mode == "signed"
        else f"{__package__}.middleware.valiss_message"
    )
    settings.configure(
        DEBUG=False,
        SECRET_KEY=secrets.token_urlsafe(32),
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF=f"{__package__}.urls",
        MIDDLEWARE=middleware,
        VALISS={
            "OPERATOR_PUB_FILE": operator,
            "ALLOWLIST_FILE": allowlist,
        },
    )
    django.setup()


class _Server(socketserver.ThreadingMixIn, WSGIServer):
    """Threaded WSGI server; daemon threads so shutdown never hangs on a
    stuck request."""

    daemon_threads = True


class _Handler(WSGIRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # requests are not access-logged, matching the reference entries


def fatal(msg: str) -> NoReturn:
    print(f"server: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def split_addr(addr: str) -> tuple[str, int]:
    host, sep, port = addr.rpartition(":")
    if not sep:
        fatal(f"bad --addr {addr!r}: want HOST:PORT")
    try:
        return host, int(port)
    except ValueError:
        fatal(f"bad --addr {addr!r}: want HOST:PORT")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport", choices=["http"], default="http",
                        help="transport to serve (this entry is HTTP-only)")
    parser.add_argument("--addr", default="127.0.0.1:0", help="HOST:PORT to listen on")
    parser.add_argument("--operator", required=True,
                        help="file with the pinned operator public key")
    parser.add_argument("--allowlist", required=True,
                        help="file with the accepted account-token ids, one per line")
    parser.add_argument("--mode", choices=["signed", "message"], default="signed",
                        help="verification mode: signed or message")
    args = parser.parse_args()

    host, port = split_addr(args.addr)
    configure(args.mode, args.operator, args.allowlist)
    try:
        # Middleware construction loads the operator key and allowlist, so a
        # bad path or file fails here, before the ready line.
        application = get_wsgi_application()
    except (OSError, ValissError) as exc:
        fatal(str(exc))

    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())

    try:
        httpd = make_server(
            host, port, application, server_class=_Server, handler_class=_Handler
        )
    except OSError as exc:
        fatal(f"listen {args.addr}: {exc}")
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    print(f"ready {httpd.server_address[0]}:{httpd.server_address[1]}", flush=True)
    stop.wait()
    httpd.shutdown()
    httpd.server_close()


if __name__ == "__main__":
    main()
