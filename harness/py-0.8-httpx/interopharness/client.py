"""The py-0.8-httpx interop harness client (CONTRACT.md): it makes exactly one
authenticated request over HTTP and reports the raw outcome as one JSON line —
{"status": <int>, "reason": <§7 code|null>, "identity": {...}|null} — exiting 0
whether the server accepted or rejected; only infrastructure failures exit
nonzero. The point of this entry is the *shipped httpx adapter surface*: every
request travels through an ``httpx.Client`` whose ``auth`` hook attaches the
valiss credential material.

In signed mode the hook is the library's own :class:`valiss.httpauth.Auth`
(``nonce=True``: a signing client always attaches a fresh nonce, because a
replay-suppressing server requires one; bearer creds go out without one). The
one thing Auth cannot express is the contract's ``--nonce`` — a caller-fixed
replay nonce — so that case rides a minimal glue hook over the library's
public :func:`valiss.httpauth.credential_headers` instead.

In message mode the shipped :class:`valiss.httpsig.Transport` cannot drive any
interop scenario: its audience is hardwired to the request's host+path (the
contract binds tokens to ``interop://sink``), its ttl must be positive (the
contract's negative ``--ttl`` mints an already-expired token), it always
checksums the bytes actually sent (``--tamper-payload`` requires checksumming
one payload and sending another), and of the contract's four chain-delivery
modes it speaks only ``embedded`` and ``negotiate``. So message mode is a glue
``httpx.Auth`` hook mirroring Transport's flow — mint once, send, retransmit
once with the detached chain headers on the ``valiss-chain: required`` signal
— with the token minted through the library's public
:func:`valiss.message.issue_message`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any, NoReturn

import httpx

from valiss import ValissError, httpauth
from valiss import creds as vcreds
from valiss import message as vmessage
from valiss import nkeys as vnkeys
from valiss import token as vtoken

# INVOKE_PATH is the HTTP route of the harness's one protected operation;
# clients call it with POST (the reference entries' wire convention).
INVOKE_PATH = "/invoke"

# Outcome is the client's one-line report: the HTTP status, the server's §7
# reject code (null on accept), the accepted identity (null on reject), and
# "chain_required": true when the final response carried the
# chain-negotiation signal (omitted when false, like the go entry's
# omitempty).
Outcome = dict[str, Any]


def fatal(msg: str) -> NoReturn:
    print(f"client: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def outcome(response: httpx.Response) -> Outcome:
    """Fold the final response into the contract outcome: a body in neither
    contract shape leaves reason and identity null."""
    out: Outcome = {"status": response.status_code, "reason": None, "identity": None}
    if response.headers.get(vtoken.HEADER_CHAIN) == vtoken.CHAIN_REQUIRED:
        out["chain_required"] = True
    try:
        parsed = json.loads(response.text)
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


class FixedNonceAuth(httpx.Auth):
    """Signed-mode glue for the contract's ``--nonce``: the shipped
    :class:`valiss.httpauth.Auth` only mints a fresh random nonce per request
    (``nonce=True``), with no way to supply the caller-fixed value the replay
    scenarios repeat. This hook is Auth's ``auth_flow`` verbatim with the
    nonce swapped, so the header set still comes from the library's public
    :func:`valiss.httpauth.credential_headers`."""

    def __init__(self, c: vcreds.Creds, nonce: str):
        self._creds = c
        self._nonce = nonce

    def auth_flow(self, request: httpx.Request) -> Iterator[httpx.Request]:
        request.headers.update(
            httpauth.credential_headers(
                self._creds,
                request.method,
                request.headers.get("host", request.url.host),
                request.url.path,
                nonce=self._nonce,
            )
        )
        yield request


class MessageAuth(httpx.Auth):
    """Message-mode glue mirroring :class:`valiss.httpsig.Transport`'s flow
    for the contract shapes Transport cannot express (see the module
    docstring): attach a pre-minted token, deliver the chain per the
    contract's ``--chain``, and on ``negotiate`` retransmit once with the
    detached chain headers when the response carries the
    ``valiss-chain: required`` signal — the same still-valid token, like
    Transport."""

    def __init__(self, token: str, account_token: str, user_token: str, chain_mode: str):
        self._token = token
        self._account_token = account_token
        self._user_token = user_token
        self._chain = chain_mode

    def _attach_detached(self, request: httpx.Request) -> None:
        request.headers[vtoken.HEADER_CHAIN_ACCOUNT_TOKEN] = self._account_token
        request.headers[vtoken.HEADER_CHAIN_USER_TOKEN] = self._user_token

    def auth_flow(self, request: httpx.Request):
        request.headers[vtoken.HEADER_MESSAGE_TOKEN] = self._token
        if self._chain == "detached":
            self._attach_detached(request)
        response = yield request
        if (
            self._chain == "negotiate"
            and response.status_code == 401
            and response.headers.get(vtoken.HEADER_CHAIN) == vtoken.CHAIN_REQUIRED
        ):
            # The server does not know our chain: retransmit once with the
            # chain detached alongside the same still-valid token.
            self._attach_detached(request)
            yield request


def signed_auth(c: vcreds.Creds, nonce: str) -> httpx.Auth:
    """The signed-mode auth hook: the shipped httpauth.Auth unless the
    scenario fixes the nonce. Auth attaches a fresh nonce per request when the
    creds can sign; bearer creds (no seed) go out without one either way."""
    if nonce and c.seed:
        return FixedNonceAuth(c, nonce)
    try:
        return httpauth.Auth(c, nonce=True)
    except ValissError as exc:
        fatal(f"creds: {exc}")


def message_auth(
    c: vcreds.Creds,
    audience: str,
    payload: bytes,
    ttl_flag: str,
    chain_mode: str,
) -> httpx.Auth:
    """Mint the per-message proof over the payload bytes bound to the
    audience and wrap it in the sending hook. The mint parameters are derived
    the way the library's Transport derives them: the user keypair from the
    creds seed and the trust-domain epoch from the chain tokens, which must
    agree on it."""
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
    try:
        account = vtoken.verify_account(c.account_token, vtoken.issuer_of(c.account_token))
    except ValissError as exc:
        fatal(f"creds account token: {exc}")
    try:
        user_claims = vtoken.verify_user(c.user_token, account.subject)
    except ValissError as exc:
        fatal(f"creds user token: {exc}")
    if account.epoch != user_claims.epoch:
        fatal(f"creds chain epochs disagree: account {account.epoch}, user {user_claims.epoch}")

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
    return MessageAuth(token, c.account_token, c.user_token, chain_mode)


def read_bytes(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as exc:
        fatal(f"read payload: {exc}")


def call(addr: str, auth: httpx.Auth, body: bytes | None) -> Outcome:
    """Perform the one request through httpx — the adapter surface under test
    — and fold the final response (after any negotiation retransmit the auth
    hook performs) into the contract outcome."""
    url = "http://" + addr + INVOKE_PATH
    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(url, content=body, auth=auth)
    except httpx.HTTPError as exc:
        # A rejection is an outcome; a request that never completed is not.
        fatal(f"request failed: {exc}")
    return outcome(response)


def main() -> None:
    parser = argparse.ArgumentParser(prog="py-0.8-httpx-client", description=__doc__)
    parser.add_argument("--transport", choices=["http"], default="http",
                        help="transport to call (this entry is HTTP-only)")
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
        out = call(args.addr, signed_auth(c, args.nonce), None)
    else:
        payload = read_bytes(args.payload) if args.payload else b""
        # The checksum is minted over --payload; the tamper bytes, when
        # given, are what actually travels.
        send = read_bytes(args.tamper_payload) if args.tamper_payload else payload
        auth = message_auth(c, args.audience, payload, args.ttl, args.chain)
        out = call(args.addr, auth, send or None)
    print(json.dumps(out), flush=True)


if __name__ == "__main__":
    main()
