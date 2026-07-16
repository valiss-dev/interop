# Interop harness contract

The live cross-language acceptance matrix (ADR 0010, layer 2). It proves that a
valiss **server** written in language A accepts and rejects requests from a
valiss **client** written in language B exactly as the reference does, over
each transport. Where the static vectors (in `valiss-dev/spec`) prove the wire
bytes agree, this proves the transports integrate.

Every implementation supplies two runnables that speak this fixed contract. The
orchestrator drives the grid `server_lang × client_lang × transport`.

## Roles

### server

A runnable that starts a valiss-protected server and exposes exactly one
protected operation.

Invocation (flags, not positional):

```
<impl>-server --transport {http|grpc} --addr HOST:PORT \
              --operator PATH_TO_OPERATOR_PUB --allowlist PATH_TO_ALLOWLIST \
              [--mode {signed|message}]
```

- `--operator` — file with the pinned operator public key (nkey string).
- `--allowlist` — file listing the accepted account-token ids, one per line.
- `--mode signed` (default) — the credential transports (per-request signature):
  the server verifies the token chain to the pinned operator, the account
  against the allowlist, the request signature, epoch, and validity windows.
- `--mode message` — the message-token transports (per-message proof): the
  server verifies an embedded/attached message token (audience, checksum).

Behavior of the protected operation:

- **Accept** → HTTP `200` / gRPC `OK`, body/response is JSON:
  `{"ok": true, "tenant": "<account name or key>", "user": "<user name or key or null>"}`.
- **Reject** → HTTP `401` / gRPC `UNAUTHENTICATED`, body/trailer is JSON:
  `{"ok": false, "reason": "<spec §7 reason code>"}`.

The server prints `ready <addr>` to stdout once listening, and exits cleanly on
SIGTERM.

### client

A runnable that makes exactly one authenticated request and reports the raw
outcome. It does **not** know the expected result — the orchestrator judges.

```
<impl>-client --transport {http|grpc} --addr HOST:PORT \
              --creds PATH_TO_CREDS [--nonce NONCE] [--mode {signed|message}] \
              [--audience AUD] [--payload PATH]
```

- `--creds` — a valiss creds file (token(s) + optional seed) from the fixture.
- `--nonce` — replay nonce to attach (omit for none).
- `--audience`/`--payload` — message-mode bindings.

The client performs the call and prints one JSON line to stdout:
`{"status": <int|grpc-code-string>, "reason": "<code|null>", "identity": {...}|null}`,
then exits 0 regardless of the server's answer (a rejected request is not a
client error).

## Fixture

Frozen material under `fixture/`, generated once from the reference
(`valiss-dev/valiss-go`) and committed. It is authoritative for all impls.

```
fixture/
├── gen/                 Go generator (regenerates the below; output is committed)
├── operator.pub         pinned operator public key
├── allowlist.txt        accepted account-token ids
└── creds/
    ├── account.creds     valid account-level creds (in allowlist)
    ├── user.creds        valid user-level creds
    ├── bearer.creds      bearer user token, no seed
    ├── revoked.creds     valid account token NOT in the allowlist
    ├── expired.creds     account/user token past exp
    └── wrongkey.creds    creds whose seed does not match the token subject
```

## Scenarios

`scenarios.yaml` is the language-neutral suite. Each scenario names the fixture
creds, the request shape, and the expected outcome. The orchestrator runs every
scenario for its transport against every (server, client) pair.

```yaml
- id: signed/account/valid
  transport: http
  mode: signed
  creds: account.creds
  expect: { accept: true, tenant: acme }
- id: signed/account/revoked
  transport: http
  mode: signed
  creds: revoked.creds
  expect: { accept: false, reason: not_allowlisted }
- id: signed/replay
  transport: http
  mode: signed
  creds: user.creds
  nonce: fixed-nonce-1
  repeat: 2                 # second attempt must be rejected
  expect_last: { accept: false, reason: replay }
```

Reason codes are the `spec/SPEC-1.md` §7 taxonomy, so a rejection asserts the
same code across implementations.

## Orchestrator

For each `transport`, for each `server_lang`, start that server with the
fixture; then for each `client_lang`, run every scenario through the client
against the server and compare the client's reported outcome to `expect`. A
cell `(server_lang × client_lang × transport)` passes when all its scenarios
pass; the matrix passes when all cells pass. Implementations run as containers
(one image per impl building both runnables) so the orchestrator needs no
per-language toolchain.

## Conformance

An implementation is **matrix-conformant** for a transport when, as both server
and client, it passes every scenario against the reference and against every
other conformant implementation. Server-side scenarios that require the full
request verifier (revocation via allowlist, replay) apply only once an
implementation ships that verifier; an impl may join the matrix as a
client-and-message-verifier first and add server-side signed-request
conformance later.

## Layout

```
interop/
├── CONTRACT.md          this file
├── scenarios.yaml       language-neutral scenario suite
├── fixture/             frozen keys, allowlist, creds (+ Go generator)
├── harnesses/
│   ├── go/              reference server + client
│   └── py/              Python server + client (added when it ships the verifier)
├── orchestrator/        the matrix runner + container compose
└── .github/workflows/   CI running the matrix
```
