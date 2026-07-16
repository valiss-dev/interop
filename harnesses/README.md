# harnesses

One subdirectory per implementation (`go/`, `py/`, …), each providing the
`server` and `client` runnables defined in `../CONTRACT.md`. Each builds to a
container image the orchestrator starts; behavior — not language — must match
the contract.

- `go/` — the reference harness (built first).
- `py/` — added as a client + message verifier now; a signed-request server
  once valiss-py ships the request verifier (allowlist + replay).
