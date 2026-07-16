"""Local smoke for this Django harness entry: it starts the entry's server on
a loopback port (one process per mode, so each mode gets a fresh replay
cache, as the orchestrator arranges) and drives every HTTP-applicable
scenario from the repository's scenarios.yaml against it with a client
following the py-0.8 entry's conventions plus the contract's extended
message-mode flags (--ttl, --tamper-payload, --chain; CONTRACT.md). It also
asserts the "ready <addr>" line and the clean SIGTERM exit. This proves the
entry without containers; the Dockerfile still owns the pinned interpreter.

Run it inside the entry's venv — smoke.sh builds one with the exact pins and
invokes this file. The entry id (and so the server runnable's name) is the
entry directory's own name, keeping this file identical across the Django
entries.
"""

from __future__ import annotations

import json
import re
import signal
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

import yaml

from interopharness import wire
from valiss import ValissError
from valiss import creds as vcreds
from valiss import message as vmessage
from valiss import nkeys as vnkeys
from valiss import token as vtoken

ENTRY_DIR = Path(__file__).resolve().parent
ENTRY_ID = ENTRY_DIR.name
ROOT = ENTRY_DIR.parents[1]

# The server capabilities this entry's manifest declares; a scenario whose
# `requires` names anything else is reported as skipped, like the
# orchestrator would.
FEATURES = {"allowlist", "replay", "epoch", "bearer"}

# Outcome is the client-side report the judge compares, shaped like the
# contract's client JSON line: HTTP status, §7 reject code (None on accept),
# the accepted identity (None on reject), and whether the final response
# carried the chain-negotiation signal.
Outcome = dict[str, Any]


def fatal(msg: str) -> NoReturn:
    raise SystemExit(f"smoke: {msg}")


# --- the contract's Go-syntax --ttl durations (e.g. "30s", "-5m", "1h30m") ---

_DURATION_UNIT_SECONDS = {
    "ns": 1e-9, "us": 1e-6, "µs": 1e-6, "μs": 1e-6,
    "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0,
}
_DURATION_TERM = re.compile(r"(\d+(?:\.\d*)?)(ns|us|µs|μs|ms|s|m|h)")


def parse_go_duration(text: str) -> timedelta:
    s = text.strip()
    sign = 1.0
    if s[:1] in ("+", "-"):
        sign = -1.0 if s[0] == "-" else 1.0
        s = s[1:]
    total, pos = 0.0, 0
    for m in _DURATION_TERM.finditer(s):
        if m.start() != pos:
            fatal(f"bad duration {text!r}")
        total += float(m.group(1)) * _DURATION_UNIT_SECONDS[m.group(2)]
        pos = m.end()
    if pos == 0 or pos != len(s):
        fatal(f"bad duration {text!r}")
    return timedelta(seconds=sign * total)


# --- the driving client (py-0.8 client conventions, HTTP only) ---

def outcome(status: int, body: str, chain_required: bool) -> Outcome:
    """Fold a contract response body (accept or reject shape) into the
    outcome; a body in neither shape leaves reason and identity None."""
    out: Outcome = {
        "status": status, "reason": None, "identity": None,
        "chain_required": chain_required,
    }
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


def do_http(url: str, headers: list[tuple[str, str]], body: bytes | None) -> Outcome:
    request = urllib.request.Request(url, data=body, method="POST")
    for key, value in headers:
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return outcome(
                response.status,
                response.read().decode("utf-8", "replace"),
                response.headers.get(vtoken.HEADER_CHAIN) == vtoken.CHAIN_REQUIRED,
            )
    except urllib.error.HTTPError as err:
        # A rejection is an outcome, not a client error.
        with err:
            return outcome(
                err.code,
                err.read().decode("utf-8", "replace"),
                err.headers.get(vtoken.HEADER_CHAIN) == vtoken.CHAIN_REQUIRED,
            )
    except OSError as exc:
        fatal(f"request failed: {exc}")


def signed(addr: str, c: vcreds.Creds, nonce: str) -> Outcome:
    """Make one credential-signed (or bearer) request. A seed is used as
    given — even one that does not match the token subject — since the
    server's rejection is what the smoke tests."""
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
    url = "http://" + addr + wire.INVOKE_PATH
    if signer is not None:
        if nonce:
            headers.append((vtoken.HEADER_NONCE, nonce))
        context = wire.http_request_context(
            "POST", urlsplit(url).netloc, wire.INVOKE_PATH, nonce
        )
        try:
            timestamp, signature = vtoken.sign_request(signer, context)
        except ValissError as exc:
            fatal(f"sign request: {exc}")
        headers.append((vtoken.HEADER_TIMESTAMP, timestamp))
        headers.append((vtoken.HEADER_SIGNATURE, signature))
    return do_http(url, headers, None)


def message(
    addr: str,
    c: vcreds.Creds,
    audience: str,
    payload: bytes,
    send_payload: bytes,
    ttl: timedelta,
    chain_mode: str,
) -> Outcome:
    """Mint a per-message proof over the checksummed payload bytes bound to
    the audience and send the (possibly tampered) payload plus token, with
    the chain delivered per --chain: embedded in the token, detached in the
    chain headers, absent, or negotiated (bare first, retransmitted with the
    detached headers once on the valiss-chain: required signal)."""
    if not c.account_token or not c.user_token or not c.seed:
        fatal("message mode requires bundle creds: account token, user token, and seed")
    try:
        user = vnkeys.from_seed(c.seed)
    except ValissError as exc:
        fatal(f"creds seed: {exc}")
    # The trust-domain epoch comes from the chain tokens, which must agree
    # on it (mirrors the py-0.8 client).
    try:
        account = vtoken.verify_account(c.account_token, vtoken.issuer_of(c.account_token))
        user_claims = vtoken.verify_user(c.user_token, account.subject)
    except ValissError as exc:
        fatal(f"creds chain: {exc}")
    if account.epoch != user_claims.epoch:
        fatal(f"creds chain epochs disagree: account {account.epoch}, user {user_claims.epoch}")

    # A non-positive --ttl mints an already-expired token (CONTRACT.md);
    # issue_message insists ttl be positive, so the expired case rides the
    # absolute-expiry parameter instead.
    validity: dict[str, Any] = (
        {"ttl": ttl}
        if ttl > timedelta(0)
        else {"expiry": datetime.now(timezone.utc) + ttl}
    )
    try:
        token = vmessage.issue_message(
            user,
            audience=audience,
            checksum=vmessage.checksum(payload),
            chain=(c.account_token, c.user_token) if chain_mode == "embedded" else None,
            epoch=user_claims.epoch,
            **validity,
        )
    except ValissError as exc:
        fatal(f"issue message token: {exc}")

    url = "http://" + addr + wire.INVOKE_PATH
    detached = [
        (vtoken.HEADER_CHAIN_ACCOUNT_TOKEN, c.account_token),
        (vtoken.HEADER_CHAIN_USER_TOKEN, c.user_token),
    ]
    headers = [(vtoken.HEADER_MESSAGE_TOKEN, token)]
    if chain_mode == "detached":
        headers += detached
    out = do_http(url, headers, send_payload or None)
    if chain_mode == "negotiate" and out["status"] == 401 and out["chain_required"]:
        out = do_http(url, headers + detached, send_payload or None)
    return out


# --- scenario driving and judging (mirrors the orchestrator's judge) ---

def run_scenario(sc: dict[str, Any], addr: str) -> list[Outcome]:
    c = vcreds.load(str(ROOT / "fixture" / "creds" / sc["creds"]))
    outs: list[Outcome] = []
    for _ in range(sc.get("repeat") or 1):
        if sc["mode"] == "signed":
            outs.append(signed(addr, c, sc.get("nonce") or ""))
        else:
            payload = (ROOT / sc["payload"]).read_bytes() if sc.get("payload") else b""
            send = (
                (ROOT / sc["tamper_payload"]).read_bytes()
                if sc.get("tamper_payload")
                else payload
            )
            ttl = (
                parse_go_duration(sc["ttl"])
                if sc.get("ttl")
                else vmessage.DEFAULT_MESSAGE_TTL
            )
            outs.append(
                message(
                    addr, c, sc.get("audience") or "", payload, send, ttl,
                    sc.get("chain") or "embedded",
                )
            )
    return outs


def judge(sc: dict[str, Any], outs: list[Outcome]) -> str | None:
    """Compare the outcomes to the scenario expectation; every pre-final
    repeat attempt must be accepted. Returns the mismatch, or None."""
    want = sc.get("expect_last") or sc["expect"]
    for out in outs[:-1]:
        if out["status"] != 200:
            return f"warmup expected accept, got {out}"
    out = outs[-1]
    if "chain_required" in want and out["chain_required"] != bool(want["chain_required"]):
        return f"chain_required = {out['chain_required']}, want {want['chain_required']}"
    if want.get("accept"):
        if out["status"] != 200:
            return f"expected accept, got {out}"
        if out["reason"] is not None:
            return f"accept carried reason {out['reason']!r}"
        if out["identity"] is None:
            return "accept carried no identity"
        if "tenant" in want and out["identity"]["tenant"] != want["tenant"]:
            return f"tenant = {out['identity']['tenant']!r}, want {want['tenant']!r}"
        if "user" in want and out["identity"]["user"] != want["user"]:
            return f"user = {out['identity']['user']!r}, want {want['user']!r}"
        return None
    if out["status"] != 401:
        return f"expected reject with reason {want.get('reason')!r}, got {out}"
    if out["reason"] != want.get("reason"):
        return f"reason = {out['reason']!r}, want {want.get('reason')!r}"
    if out["identity"] is not None:
        return f"reject carried identity {out['identity']}"
    return None


# --- server lifecycle ---

@contextmanager
def server(mode: str) -> Iterator[str]:
    """Start the entry's server runnable from this venv, yield the bound
    address from its ready line, and assert the clean SIGTERM exit."""
    binary = Path(sys.executable).parent / f"{ENTRY_ID}-server"
    proc = subprocess.Popen(
        [
            str(binary), "--transport", "http", "--addr", "127.0.0.1:0",
            "--operator", str(ROOT / "fixture" / "operator.pub"),
            "--allowlist", str(ROOT / "fixture" / "allowlist.txt"),
            "--mode", mode,
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout is not None  # PIPE above
        line = _readline(proc.stdout, timeout=30.0)
        if not line.startswith("ready "):
            fatal(f"server ({mode}) did not report readiness: {line!r}")
        yield line.removeprefix("ready ").strip()
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            fatal(f"server ({mode}) did not exit on SIGTERM")
        if code != 0:
            fatal(f"server ({mode}) exited {code} on SIGTERM, want 0")


def _readline(stream: Any, timeout: float) -> str:
    got: dict[str, str] = {}
    reader = threading.Thread(target=lambda: got.update(line=stream.readline()), daemon=True)
    reader.start()
    reader.join(timeout)
    return got.get("line", "")


def main() -> int:
    suite = yaml.safe_load((ROOT / "scenarios.yaml").read_text(encoding="utf-8"))
    applicable = [s for s in suite["scenarios"] if s.get("transport") in (None, "http")]
    passed = failed = skipped = 0
    for mode in ("signed", "message"):
        subset = [s for s in applicable if s.get("mode") == mode]
        if not subset:
            continue
        with server(mode) as addr:
            for sc in subset:
                if not set(sc.get("requires") or ()) <= FEATURES:
                    print(f"SKIP {sc['id']} (requires {sc['requires']})")
                    skipped += 1
                    continue
                err = judge(sc, run_scenario(sc, addr))
                if err is None:
                    print(f"PASS {sc['id']}")
                    passed += 1
                else:
                    print(f"FAIL {sc['id']}: {err}")
                    failed += 1
    print(f"{ENTRY_ID} smoke: {passed} passed, {failed} failed, {skipped} skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
