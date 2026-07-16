"""The py-0.8 interop harness server (CONTRACT.md): it exposes exactly one
protected operation over HTTP or gRPC, mirroring go-0.12's cmd/server.

In signed mode it runs the valiss Verifier against the pinned operator key
and the file-backed allowlist, with a replay cache (signed requests must
carry a nonce) and bearer user tokens accepted. In message mode it verifies
a per-message proof of origin: audience pinned to the interop sink, checksum
bound to the received payload, and the chain's account checked against the
same allowlist. The chain arrives embedded in the token or in the detached
request headers (valiss-chain-account-token / valiss-chain-user-token); a
token with no chain anywhere is rejected no_chain and the response carries
the chain-negotiation signal valiss-chain: required (response header on
HTTP, trailer on gRPC).

Accept answers HTTP 200 / gRPC OK with the contract's accept JSON; reject
answers HTTP 401 / gRPC UNAUTHENTICATED with {"ok":false,"reason":<§7>}.
It prints "ready <addr>" once listening and exits cleanly on SIGTERM.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from typing import Any, NoReturn
from urllib.parse import urlsplit

from valiss import MemoryReplayCache, Reason, Request, StaticAllowlist, Verifier, ValissError
from valiss import message as vmessage
from valiss import token as vtoken

from . import wire

# One request's verdict: (accept shape, None) or (None, reject shape), plus
# whether the rejection must carry the valiss-chain: required negotiation
# signal (response header on HTTP, trailer on gRPC).
Outcome = tuple[dict[str, Any] | None, dict[str, Any] | None, bool]

# Every ValissError raised on the verification paths carries a §7 reason; an
# unmapped failure would be a harness bug best surfaced by a matrix mismatch,
# not a crash — the same fallback the go-0.12 entry's substring table uses.
_FALLBACK_REASON = "malformed"


def _reason(exc: ValissError) -> str:
    return str(exc.reason) if exc.reason is not None else _FALLBACK_REASON


class Service:
    """The verification state shared by both transports."""

    def __init__(self, mode: str, operator_pub: str, allowlist: StaticAllowlist):
        self.mode = mode
        self.operator_pub = operator_pub
        self.allowlist = allowlist
        self.verifier = Verifier(operator_pub, allowlist, replay_cache=MemoryReplayCache())

    def verify_signed(self, request: Request) -> Outcome:
        """Run the request-credential verification and render the contract
        outcome: the accept shape, or the reject shape with the §7 code."""
        try:
            identity = self.verifier.verify(request)
        except ValissError as exc:
            return None, wire.reject(_reason(exc)), False
        user = identity.user.name if identity.user is not None else None
        return wire.accept(identity.account.name, user), None, False

    def verify_message(
        self, token: str, payload: bytes, chain_account: str, chain_user: str
    ) -> Outcome:
        """Verify a per-message proof over the payload as received, with the
        audience pinned to the interop sink and the chain's account held to
        the same allowlist the signed mode enforces. Detached chain material
        from the request headers supplies the chain for a chainless token,
        the way the library's own transports resolve it; a token with no
        chain anywhere reports chain-required, telling the transport to
        attach the valiss-chain: required negotiation signal."""
        if not token:
            return None, wire.reject("missing"), False
        kwargs: dict[str, Any] = {"audience": wire.SINK_AUDIENCE, "payload": payload}
        if chain_account and chain_user:
            kwargs["chain"] = (chain_account, chain_user)
        try:
            claims = vmessage.verify_message(token, self.operator_pub, **kwargs)
        except ValissError as exc:
            return None, wire.reject(_reason(exc)), exc.reason == Reason.NO_CHAIN
        assert claims.account is not None and claims.user is not None  # chain-verified
        if claims.account.id not in self.allowlist:
            return None, wire.reject("not_allowlisted"), False
        return wire.accept(claims.account.name, claims.user.name), None, False

    def handle(self, headers: _Headers, payload: bytes, context: bytes) -> Outcome:
        """Dispatch one request's credential material by mode. ``headers`` is
        a first-value lookup over the transport's headers/metadata;
        ``context`` the transport's canonical request-context bytes."""
        if self.mode == "signed":
            return self.verify_signed(
                Request(
                    account_token=headers.get(vtoken.HEADER_ACCOUNT_TOKEN),
                    user_token=headers.get(vtoken.HEADER_USER_TOKEN),
                    timestamp=headers.get(vtoken.HEADER_TIMESTAMP),
                    signature=headers.get(vtoken.HEADER_SIGNATURE),
                    context=context,
                    nonce=headers.get(vtoken.HEADER_NONCE),
                )
            )
        return self.verify_message(
            headers.get(vtoken.HEADER_MESSAGE_TOKEN),
            payload,
            headers.get(vtoken.HEADER_CHAIN_ACCOUNT_TOKEN),
            headers.get(vtoken.HEADER_CHAIN_USER_TOKEN),
        )


class _Headers:
    """First-value lookup over header/metadata pairs, keyed case-insensitively
    (HTTP header names arrive canonicalized, gRPC metadata keys lowercase)."""

    def __init__(self, pairs: list[tuple[str, str]]):
        self._first: dict[str, str] = {}
        for key, value in pairs:
            self._first.setdefault(key.lower(), value)

    def get(self, key: str) -> str:
        return self._first.get(key, "")


def serve_http(service: Service, host: str, port: int, stop: threading.Event) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass  # requests are not access-logged, matching the go entry

        def do_POST(self) -> None:  # noqa: N802 - http.server naming
            path = urlsplit(self.path).path
            if path != wire.INVOKE_PATH:
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            nonce = self.headers.get(vtoken.HEADER_NONCE) or ""
            # The signed host mirrors the reference transports' derivation:
            # the request Host (SPEC-1.md §5.3).
            context = wire.http_request_context(
                self.command, self.headers.get("Host") or "", path, nonce
            )
            accepted, rejected, chain_required = service.handle(
                _Headers(self.headers.items()), body, context
            )
            raw = json.dumps(rejected if rejected is not None else accepted).encode()
            self.send_response(401 if rejected is not None else 200)
            if rejected is not None and chain_required:
                self.send_header(vtoken.HEADER_CHAIN, vtoken.CHAIN_REQUIRED)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    httpd = ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    announce_ready(httpd.server_address[0], httpd.server_address[1])
    stop.wait()
    httpd.shutdown()
    httpd.server_close()


def serve_grpc(service: Service, host: str, port: int, stop: threading.Event) -> None:
    from concurrent import futures

    import grpc
    from interoppb import interop_pb2, interop_pb2_grpc

    class Servicer(interop_pb2_grpc.InteropServicer):
        def Invoke(self, request: Any, context: grpc.ServicerContext) -> Any:  # noqa: N802
            headers = _Headers(
                [(k, v) for k, v in context.invocation_metadata() if isinstance(v, str)]
            )
            nonce = headers.get(vtoken.HEADER_NONCE)
            signed_context = wire.grpc_request_context(wire.GRPC_FULL_METHOD, nonce)
            accepted, rejected, chain_required = service.handle(
                headers, request.payload, signed_context
            )
            if rejected is not None:
                # Rejections travel as an UNAUTHENTICATED status whose message
                # is the contract's reject JSON, exactly like go-0.12; a
                # no_chain rejection also carries the valiss-chain: required
                # trailer.
                if chain_required:
                    context.set_trailing_metadata(
                        ((vtoken.HEADER_CHAIN, vtoken.CHAIN_REQUIRED),)
                    )
                context.abort(grpc.StatusCode.UNAUTHENTICATED, json.dumps(rejected))
            return interop_pb2.InvokeResponse(json=json.dumps(accepted))

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    interop_pb2_grpc.add_InteropServicer_to_server(Servicer(), server)
    bound = server.add_insecure_port(f"{host}:{port}")
    if bound == 0:
        fatal(f"listen {host}:{port}: cannot bind")
    server.start()
    announce_ready(host, bound)
    stop.wait()
    server.stop(grace=5).wait()


def announce_ready(host: str, port: int) -> None:
    """Print the contract's readiness line with the bound address."""
    print(f"ready {host}:{port}", flush=True)


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
    parser = argparse.ArgumentParser(prog="py-0.8-server", description=__doc__)
    parser.add_argument("--transport", choices=["http", "grpc"], default="http",
                        help="transport to serve: http or grpc")
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

    service = Service(args.mode, operator_pub, allowlist)
    host, port = split_addr(args.addr)

    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())

    if args.transport == "http":
        serve_http(service, host, port, stop)
    else:
        serve_grpc(service, host, port, stop)


if __name__ == "__main__":
    main()
