# interop

The live cross-language interop matrix for valiss (ADR 0010, layer 2). It runs
the grid `server_lang × client_lang × transport` and proves that a valiss
server in one language accepts/rejects requests from a client in another exactly
as the reference does.

This complements the static conformance vectors in `valiss-dev/spec` (which
prove the wire *bytes* agree). This proves the *transports* integrate.

- **`CONTRACT.md`** — the harness contract every implementation implements
  (server + client runnables, fixture, scenario schema).
- **`scenarios.yaml`** — the language-neutral scenario suite.
- **`fixture/`** — frozen keys, allowlist, and creds, generated from the Go
  reference.
- **`harnesses/<impl>/`** — each implementation's server + client.
- **`orchestrator/`** — the matrix runner (containers + compose).

## Status

Foundation. The contract, scenarios, and structure are defined. Next: generate
the fixture from `valiss-go`, build the Go reference harness, then the
orchestrator. Python joins as a client + message verifier now, and as a
signed-request server once it ships the request verifier (allowlist + replay).
