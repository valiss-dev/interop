"""Local smoke for this httpx client entry: it builds the go-0.12 reference
server from the sibling entry (the known-good verifier, like the orchestrator
pairs entries), starts it on a loopback port against the committed fixture
(one process per mode, so each mode gets a fresh replay cache), and drives
every HTTP-applicable scenario from the repository's scenarios.yaml through
this entry's client runnable, judging its printed outcome line. This proves
the entry without containers; the Dockerfile still owns the pinned
interpreter.

Run it inside the entry's venv — smoke.sh builds one with the exact pins and
invokes this file. The entry id (and so the client runnable's name) is the
entry directory's own name.
"""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, NoReturn

import yaml

ENTRY_DIR = Path(__file__).resolve().parent
ENTRY_ID = ENTRY_DIR.name
ROOT = ENTRY_DIR.parents[1]
REFERENCE_DIR = ENTRY_DIR.parent / "go-0.12"

# The reference server's capabilities (go-0.12's manifest server.features); a
# scenario whose `requires` names anything else is reported as skipped, like
# the orchestrator would.
FEATURES = {"allowlist", "replay", "epoch", "bearer"}

# Outcome is the client's parsed one-line report (CONTRACT.md): HTTP status,
# §7 reject code (None on accept), the accepted identity (None on reject),
# and — when true — the chain-negotiation signal on the final response.
Outcome = dict[str, Any]


def fatal(msg: str) -> NoReturn:
    raise SystemExit(f"smoke: {msg}")


def build_reference_server(workdir: Path) -> Path:
    """Build the go-0.12 reference server the client is proven against."""
    binary = workdir / "server"
    proc = subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/server"],
        cwd=REFERENCE_DIR,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        fatal(f"build go-0.12 server: {proc.stderr}")
    return binary


# --- driving this entry's client runnable ---

def run_client(sc: dict[str, Any], addr: str) -> list[Outcome]:
    """Invoke the entry's client once per repeat attempt with the scenario's
    contract flags and parse its outcome lines. The client must exit 0
    whether the request was accepted or rejected."""
    binary = Path(sys.executable).parent / f"{ENTRY_ID}-client"
    args = [
        str(binary), "--transport", "http", "--addr", addr,
        "--creds", str(ROOT / "fixture" / "creds" / sc["creds"]),
    ]
    if sc.get("nonce"):
        args += ["--nonce", sc["nonce"]]
    if sc["mode"] == "message":
        args += ["--mode", "message"]
        if sc.get("audience"):
            args += ["--audience", sc["audience"]]
        if sc.get("payload"):
            args += ["--payload", str(ROOT / sc["payload"])]
        if sc.get("tamper_payload"):
            args += ["--tamper-payload", str(ROOT / sc["tamper_payload"])]
        if sc.get("ttl"):
            args += ["--ttl=" + str(sc["ttl"])]
        if sc.get("chain"):
            args += ["--chain", sc["chain"]]

    outs: list[Outcome] = []
    for _ in range(sc.get("repeat") or 1):
        proc = subprocess.run(args, capture_output=True, text=True)
        if proc.returncode != 0:
            fatal(f"client {args}: exit {proc.returncode}: {proc.stderr}")
        try:
            outs.append(json.loads(proc.stdout))
        except json.JSONDecodeError as exc:
            fatal(f"client output {proc.stdout!r}: {exc}")
    return outs


# --- judging (mirrors the orchestrator's judge) ---

def judge(sc: dict[str, Any], outs: list[Outcome]) -> str | None:
    """Compare the outcomes to the scenario expectation; every pre-final
    repeat attempt must be accepted. Returns the mismatch, or None."""
    want = sc.get("expect_last") or sc["expect"]
    for out in outs[:-1]:
        if out["status"] != 200:
            return f"warmup expected accept, got {out}"
    out = outs[-1]
    got_chain = bool(out.get("chain_required"))
    if "chain_required" in want and got_chain != bool(want["chain_required"]):
        return f"chain_required = {got_chain}, want {want['chain_required']}"
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


# --- reference server lifecycle ---

@contextmanager
def server(binary: Path, mode: str) -> Iterator[str]:
    """Start the reference server, yield the bound address from its ready
    line, and assert the clean SIGTERM exit."""
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
            fatal(f"reference server ({mode}) did not report readiness: {line!r}")
        yield line.removeprefix("ready ").strip()
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            fatal(f"reference server ({mode}) did not exit on SIGTERM")
        if code != 0:
            fatal(f"reference server ({mode}) exited {code} on SIGTERM, want 0")


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
    with tempfile.TemporaryDirectory() as tmp:
        binary = build_reference_server(Path(tmp))
        for mode in ("signed", "message"):
            subset = [s for s in applicable if s.get("mode") == mode]
            if not subset:
                continue
            with server(binary, mode) as addr:
                for sc in subset:
                    if not set(sc.get("requires") or ()) <= FEATURES:
                        print(f"SKIP {sc['id']} (requires {sc['requires']})")
                        skipped += 1
                        continue
                    err = judge(sc, run_client(sc, addr))
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
