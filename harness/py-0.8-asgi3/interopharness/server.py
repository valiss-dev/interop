"""The ASGI interop harness server for the valiss-py 0.8 series
(CONTRACT.md): it exposes exactly one protected operation over HTTP — a
minimal raw ASGI app wrapped by the library's shipped pure-ASGI middlewares
(see :mod:`.app` for the stack and the contract adaptations around it).

The stack runs under uvicorn, single-process by construction: one
MemoryReplayCache must see every nonce, where a pre-forking server would
shard the cache across workers. Lifespan is off — the stack has no startup
hooks, and the verification state loads before the ready line so a bad
operator or allowlist path fails fast. It prints "ready <addr>" once
listening and exits cleanly on SIGTERM (uvicorn's own signal handling
drains and returns).
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
from typing import NoReturn

import uvicorn

from valiss import StaticAllowlist, ValissError

from . import app as appstack


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


def _install_signals(server: uvicorn.Server) -> None:
    """The contract wants a clean zero exit on SIGTERM, but uvicorn re-raises
    the captured signal after its graceful shutdown so process managers see
    the conventional signal death. Keeping a harness handler installed covers
    both ends: uvicorn saves and restores it around ``serve()``, so the
    re-raise lands here (the shutdown it asks for has already happened), and
    a signal racing in before uvicorn's own capture still requests exit."""

    def handle(signum: int, frame: object) -> None:
        server.should_exit = True

    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, handle)


async def _serve(server: uvicorn.Server, sock, addr: str) -> None:
    """Run uvicorn over the pre-bound socket and print the contract's
    readiness line once it is accepting connections. A startup failure
    surfaces through the serve task instead of a ready line."""
    task = asyncio.ensure_future(server.serve(sockets=[sock]))
    while not server.started and not task.done():
        await asyncio.sleep(0.01)
    if not task.done():
        print(f"ready {addr}", flush=True)
    await task


def main() -> None:
    parser = argparse.ArgumentParser(prog="py-0.8-asgi3-server", description=__doc__)
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

    try:
        with open(args.operator, encoding="utf-8") as f:
            operator_pub = f.read().strip()
    except OSError as exc:
        fatal(f"read operator key: {exc}")
    try:
        allowlist = StaticAllowlist.from_file(args.allowlist)
    except ValissError as exc:
        fatal(f"load allowlist: {exc}")

    application = appstack.build(args.mode, operator_pub, allowlist)
    host, port = split_addr(args.addr)

    config = uvicorn.Config(
        application,
        host=host,
        port=port,
        # Single process (no workers): the replay cache must not shard.
        log_level="warning",
        access_log=False,
        lifespan="off",
    )
    server = uvicorn.Server(config)
    try:
        sock = config.bind_socket()
    except OSError as exc:
        fatal(f"listen {args.addr}: {exc}")
    bound_host, bound_port = sock.getsockname()[:2]
    _install_signals(server)
    asyncio.run(_serve(server, sock, f"{bound_host}:{bound_port}"))


if __name__ == "__main__":
    main()
