"""The py-0.8 interop harness client (CONTRACT.md): it makes exactly one
authenticated request and reports the raw outcome as one JSON line —
{"status": <int|grpc-code-string>, "reason": <§7 code|null>,
"identity": {...}|null} — exiting 0 whether the server accepted or rejected;
only infrastructure failures exit nonzero. It mirrors go-0.12's cmd/client.

In signed mode creds with a seed sign the request with it as given — even a
seed that does not match the token subject is used verbatim, since the
server's rejection is what the matrix tests; creds without a seed go out as
bearer requests. Signing clients always attach a nonce: the --nonce value
when fixed by the scenario, a fresh random one otherwise, because a
replay-suppressing server (like this entry's) requires one on every signed
request. In message mode the client mints a message token over the --payload
bytes bound to --audience, with the creds' chain embedded.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any, NoReturn
from urllib.parse import urlsplit

from valiss import ValissError
from valiss import creds as vcreds
from valiss import message as vmessage
from valiss import nkeys as vnkeys
from valiss import token as vtoken

from . import wire

# Outcome is the client's one-line report: the HTTP status int or the
# canonical gRPC code string, the server's §7 reject code (null on accept),
# and the accepted identity (null on reject).
Outcome = dict[str, Any]


def fatal(msg: str) -> NoReturn:
    print(f"client: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def outcome(status: int | str, body: str) -> Outcome:
    """Fold a contract response body (accept or reject shape) into the
    outcome; a body in neither shape leaves reason and identity null."""
    out: Outcome = {"status": status, "reason": None, "identity": None}
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return out
    if not isinstance(parsed, dict):
        return out
    if parsed.get("ok") is True:
        out["identity"] = {"tenant": parsed.get("tenant") or "", "user": parsed.get("user")}
        return out
    reason = parsed.get("reason")
    if isinstance(reason, str) and reason:
        out["reason"] = reason
    return out


def signed(transport: str, addr: str, c: vcreds.Creds, nonce: str) -> Outcome:
    """Make one credential-signed (or bearer) request."""
    signer = None
    if c.seed:
        try:
            signer = vnkeys.from_seed(c.seed)
        except ValissError as exc:
            fatal(f"creds seed: {exc}")
        if not nonce:
            nonce = vtoken.new_nonce()
    else:
        # Bearer creds carry no signature, so a nonce would bind nothing.
        nonce = ""

    headers: list[tuple[str, str]] = []
    if c.account_token:
        headers.append((vtoken.HEADER_ACCOUNT_TOKEN, c.account_token))
    if c.user_token:
        headers.append((vtoken.HEADER_USER_TOKEN, c.user_token))

    if transport == "http":
        url = "http://" + addr + wire.INVOKE_PATH
        if signer is not None:
            if nonce:
                headers.append((vtoken.HEADER_NONCE, nonce))
            context = wire.http_request_context(
                "POST", urlsplit(url).netloc, wire.INVOKE_PATH, nonce
            )
            timestamp, signature = sign(signer, context)
            headers.append((vtoken.HEADER_TIMESTAMP, timestamp))
            headers.append((vtoken.HEADER_SIGNATURE, signature))
        return do_http(url, headers, None)
    if transport == "grpc":
        if signer is not None:
            if nonce:
                headers.append((vtoken.HEADER_NONCE, nonce))
            context = wire.grpc_request_context(wire.GRPC_FULL_METHOD, nonce)
            timestamp, signature = sign(signer, context)
            headers.append((vtoken.HEADER_TIMESTAMP, timestamp))
            headers.append((vtoken.HEADER_SIGNATURE, signature))
        return do_grpc(addr, headers, b"")
    fatal(f"unknown transport {transport!r}")


def message(transport: str, addr: str, c: vcreds.Creds, audience: str, payload_path: str) -> Outcome:
    """Mint a per-message proof over the payload bytes bound to the audience,
    with the creds' chain embedded, and send payload plus token."""
    if not c.account_token or not c.user_token or not c.seed:
        fatal("message mode requires bundle creds: account token, user token, and seed")
    try:
        user = vnkeys.from_seed(c.seed)
    except ValissError as exc:
        fatal(f"creds seed: {exc}")
    # The trust-domain epoch comes from the chain tokens, which must agree
    # on it (mirrors the contrib emitters' minter).
    try:
        account_issuer = vtoken.issuer_of(c.account_token)
        account = vtoken.verify_account(c.account_token, account_issuer)
    except ValissError as exc:
        fatal(f"creds account token: {exc}")
    try:
        user_claims = vtoken.verify_user(c.user_token, account.subject)
    except ValissError as exc:
        fatal(f"creds user token: {exc}")
    if account.epoch != user_claims.epoch:
        fatal(f"creds chain epochs disagree: account {account.epoch}, user {user_claims.epoch}")

    payload = b""
    if payload_path:
        try:
            with open(payload_path, "rb") as f:
                payload = f.read()
        except OSError as exc:
            fatal(f"read payload: {exc}")

    try:
        token = vmessage.issue_message(
            user,
            audience=audience,
            checksum=vmessage.checksum(payload),
            chain=(c.account_token, c.user_token),
            epoch=user_claims.epoch,
            ttl=vmessage.DEFAULT_MESSAGE_TTL,
        )
    except ValissError as exc:
        fatal(f"issue message token: {exc}")

    headers = [(vtoken.HEADER_MESSAGE_TOKEN, token)]
    if transport == "http":
        return do_http("http://" + addr + wire.INVOKE_PATH, headers, payload or None)
    if transport == "grpc":
        return do_grpc(addr, headers, payload)
    fatal(f"unknown transport {transport!r}")


def sign(signer: vnkeys.KeyPair, context: bytes) -> tuple[str, str]:
    try:
        return vtoken.sign_request(signer, context)
    except ValissError as exc:
        fatal(f"sign request: {exc}")


def do_http(url: str, headers: list[tuple[str, str]], body: bytes | None) -> Outcome:
    """Perform the one HTTP request and fold the response into the contract
    outcome."""
    request = urllib.request.Request(url, data=body, method="POST")
    for key, value in headers:
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return outcome(response.status, response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as err:
        # A rejection is an outcome, not a client error.
        with err:
            return outcome(err.code, err.read().decode("utf-8", "replace"))
    except OSError as exc:
        fatal(f"request failed: {exc}")


def do_grpc(addr: str, metadata: list[tuple[str, str]], payload: bytes) -> Outcome:
    """Perform the one gRPC call and fold the status into the contract
    outcome. UNAVAILABLE means the server never answered: an infrastructure
    error, not an outcome."""
    import grpc
    from interoppb import interop_pb2, interop_pb2_grpc

    with grpc.insecure_channel(addr) as channel:
        stub = interop_pb2_grpc.InteropStub(channel)
        try:
            response = stub.Invoke(
                interop_pb2.InvokeRequest(payload=payload), metadata=metadata, timeout=30
            )
        except grpc.RpcError as err:
            code = err.code()
            if code in (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED):
                fatal(f"call failed: {err}")
            # StatusCode names are the canonical wire spellings, which the
            # contract's "grpc code string" means.
            return outcome(code.name, err.details() or "")
        return outcome(grpc.StatusCode.OK.name, response.json)


def main() -> None:
    parser = argparse.ArgumentParser(prog="py-0.8-client", description=__doc__)
    parser.add_argument("--transport", choices=["http", "grpc"], default="http",
                        help="transport to call: http or grpc")
    parser.add_argument("--addr", required=True, help="HOST:PORT of the server")
    parser.add_argument("--creds", required=True, help="valiss creds file from the fixture")
    parser.add_argument("--nonce", default="",
                        help="fixed replay nonce (default: a fresh random nonce per signed request)")
    parser.add_argument("--mode", choices=["signed", "message"], default="signed",
                        help="request mode: signed or message")
    parser.add_argument("--audience", default="", help="message-mode audience binding")
    parser.add_argument("--payload", default="", help="message-mode payload file")
    args = parser.parse_args()

    try:
        c = vcreds.load(args.creds)
    except ValissError as exc:
        fatal(f"load creds: {exc}")

    if args.mode == "signed":
        out = signed(args.transport, args.addr, c, args.nonce)
    else:
        out = message(args.transport, args.addr, c, args.audience, args.payload)
    print(json.dumps(out), flush=True)


if __name__ == "__main__":
    main()
