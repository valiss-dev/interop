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
bytes bound to --audience with the --ttl lifetime (Go duration syntax;
negative mints an already-expired token), sends the --tamper-payload bytes
instead when given, and delivers the creds' chain per --chain: embedded in
the token (default), detached in the chain headers, none at all, or
negotiate — bare first, retransmitting once with the detached headers when
the response carries the valiss-chain: required signal. The outcome line
reports "chain_required": true when the final response carried that signal.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
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
# the accepted identity (null on reject), and "chain_required": true when
# the final response carried the chain-negotiation signal (omitted when
# false, like the go entry's omitempty).
Outcome = dict[str, Any]


def fatal(msg: str) -> NoReturn:
    print(f"client: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def outcome(status: int | str, body: str, chain_required: bool = False) -> Outcome:
    """Fold a contract response body (accept or reject shape) into the
    outcome; a body in neither shape leaves reason and identity null."""
    out: Outcome = {"status": status, "reason": None, "identity": None}
    if chain_required:
        out["chain_required"] = True
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


# One Go-duration term: a decimal number and its unit, e.g. "5m" or "1.5h"
# (time.ParseDuration syntax; a duration is a signed sequence of terms).
_DURATION_TERM = re.compile(r"(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)")

_DURATION_UNITS = {
    "ns": 1e-9, "us": 1e-6, "µs": 1e-6, "μs": 1e-6,
    "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0,
}


def parse_go_duration(text: str) -> timedelta:
    """Parse a Go time.ParseDuration string ("30s", "-5m", "1h30m"): an
    optional sign, then one or more number+unit terms; a bare "0" is the
    zero duration. Raises ValueError on anything else."""
    rest = text
    sign = 1
    if rest[:1] in ("+", "-"):
        sign = -1 if rest[0] == "-" else 1
        rest = rest[1:]
    if rest == "0":
        return timedelta(0)
    total = 0.0
    pos = 0
    for m in _DURATION_TERM.finditer(rest):
        if m.start() != pos:
            break
        total += float(m.group(1)) * _DURATION_UNITS[m.group(2)]
        pos = m.end()
    if pos == 0 or pos != len(rest):
        raise ValueError(f"invalid duration {text!r}")
    return timedelta(seconds=sign * total)


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


def message(
    transport: str,
    addr: str,
    c: vcreds.Creds,
    audience: str,
    payload_path: str,
    tamper_path: str,
    ttl_flag: str,
    chain_mode: str,
) -> Outcome:
    """Mint a per-message proof over the payload bytes bound to the audience,
    and send the payload (or the tamper bytes) plus token, with the chain
    delivered per ``chain_mode``: embedded in the token, detached in the
    chain headers, none at all, or negotiated — bare first, retransmitted
    once with the detached headers on the valiss-chain: required signal."""
    try:
        ttl = parse_go_duration(ttl_flag)
    except ValueError as exc:
        fatal(f"parse ttl: {exc}")
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

    payload = read_bytes(payload_path) if payload_path else b""
    # The checksum is minted over --payload; the tamper bytes, when given,
    # are what actually travels.
    send = read_bytes(tamper_path) if tamper_path else payload

    mint_kwargs: dict[str, Any] = {
        "audience": audience,
        "checksum": vmessage.checksum(payload),
        "epoch": user_claims.epoch,
    }
    if chain_mode == "embedded":
        mint_kwargs["chain"] = (c.account_token, c.user_token)
    # issue_message insists on a positive ttl, so an already-expired token
    # (the contract's negative --ttl) is minted via an expiry in the past.
    if ttl > timedelta(0):
        mint_kwargs["ttl"] = ttl
    else:
        mint_kwargs["expiry"] = datetime.now(timezone.utc) + ttl
    try:
        token = vmessage.issue_message(user, **mint_kwargs)
    except ValissError as exc:
        fatal(f"issue message token: {exc}")

    def attempt(detached: bool) -> Outcome:
        """One call; ``detached`` says whether the chain rides along in the
        detached headers."""
        headers = [(vtoken.HEADER_MESSAGE_TOKEN, token)]
        if detached:
            headers.append((vtoken.HEADER_CHAIN_ACCOUNT_TOKEN, c.account_token))
            headers.append((vtoken.HEADER_CHAIN_USER_TOKEN, c.user_token))
        if transport == "http":
            return do_http("http://" + addr + wire.INVOKE_PATH, headers, send or None)
        if transport == "grpc":
            return do_grpc(addr, headers, send)
        fatal(f"unknown transport {transport!r}")

    out = attempt(chain_mode == "detached")
    if chain_mode == "negotiate" and out.get("chain_required"):
        # The server does not know our chain: retransmit once with the chain
        # detached alongside the same still-valid token.
        return attempt(True)
    return out


def read_bytes(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as exc:
        fatal(f"read payload: {exc}")


def sign(signer: vnkeys.KeyPair, context: bytes) -> tuple[str, str]:
    try:
        return vtoken.sign_request(signer, context)
    except ValissError as exc:
        fatal(f"sign request: {exc}")


def do_http(url: str, headers: list[tuple[str, str]], body: bytes | None) -> Outcome:
    """Perform the one HTTP request and fold the response into the contract
    outcome, including the chain-negotiation signal header."""
    request = urllib.request.Request(url, data=body, method="POST")
    for key, value in headers:
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            chain = response.headers.get(vtoken.HEADER_CHAIN) == vtoken.CHAIN_REQUIRED
            return outcome(response.status, response.read().decode("utf-8", "replace"), chain)
    except urllib.error.HTTPError as err:
        # A rejection is an outcome, not a client error.
        with err:
            chain = err.headers.get(vtoken.HEADER_CHAIN) == vtoken.CHAIN_REQUIRED
            return outcome(err.code, err.read().decode("utf-8", "replace"), chain)
    except OSError as exc:
        fatal(f"request failed: {exc}")


def chain_signal(trailing: Iterable[tuple[str, str | bytes]] | None) -> bool:
    """Whether gRPC trailing metadata carries the valiss-chain: required
    negotiation signal."""
    for key, value in trailing or ():
        if key == vtoken.HEADER_CHAIN and value == vtoken.CHAIN_REQUIRED:
            return True
    return False


def do_grpc(addr: str, metadata: list[tuple[str, str]], payload: bytes) -> Outcome:
    """Perform the one gRPC call and fold the status into the contract
    outcome, including the chain-negotiation signal trailer. UNAVAILABLE
    means the server never answered: an infrastructure error, not an
    outcome."""
    import grpc
    from interoppb import interop_pb2, interop_pb2_grpc

    with grpc.insecure_channel(addr) as channel:
        stub = interop_pb2_grpc.InteropStub(channel)
        try:
            response, call = stub.Invoke.with_call(
                interop_pb2.InvokeRequest(payload=payload), metadata=metadata, timeout=30
            )
        except grpc.RpcError as err:
            code = err.code()
            if code in (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED):
                fatal(f"call failed: {err}")
            # StatusCode names are the canonical wire spellings, which the
            # contract's "grpc code string" means. A failed unary call is
            # also a grpc.Call, so its trailing metadata is readable.
            return outcome(code.name, err.details() or "", chain_signal(err.trailing_metadata()))
        return outcome(grpc.StatusCode.OK.name, response.json, chain_signal(call.trailing_metadata()))


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
    parser.add_argument("--tamper-payload", default="", dest="tamper_payload",
                        help="message mode: send this file's bytes instead of the "
                             "checksummed --payload ones")
    parser.add_argument("--ttl", default="30s",
                        help="message-token lifetime, Go duration syntax; negative mints "
                             "an already-expired token")
    parser.add_argument("--chain", choices=["embedded", "detached", "none", "negotiate"],
                        default="embedded",
                        help="message-mode chain delivery: embedded, detached, none, "
                             "or negotiate")
    # argparse reads a leading dash as an option marker, so a negative --ttl
    # value ("-5m") must ride in the same token as its flag.
    argv = sys.argv[1:]
    for i, arg in enumerate(argv[:-1]):
        if arg == "--ttl" and argv[i + 1].startswith("-"):
            argv[i : i + 2] = ["--ttl=" + argv[i + 1]]
            break
    args = parser.parse_args(argv)

    try:
        c = vcreds.load(args.creds)
    except ValissError as exc:
        fatal(f"load creds: {exc}")

    if args.mode == "signed":
        out = signed(args.transport, args.addr, c, args.nonce)
    else:
        out = message(args.transport, args.addr, c, args.audience, args.payload,
                      args.tamper_payload, args.ttl, args.chain)
    print(json.dumps(out), flush=True)


if __name__ == "__main__":
    main()
