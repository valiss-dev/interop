# interop

The live cross-language interop matrix for valiss (ADR 0010, layer 2). It runs
the grid `server_lang × client_lang × transport` and proves that a valiss
server in one language accepts/rejects requests from a client in another exactly
as the reference does.

This complements the static conformance vectors in `valiss-dev/spec` (which
prove the wire *bytes* agree). This proves the *transports* integrate.

- **`CONTRACT.md`** — the harness contract every implementation entry
  implements (server + client runnables, fixture, scenario schema).
- **`scenarios.yaml`** — the language-neutral scenario suite.
- **`fixture/`** — frozen keys, allowlist, and creds, generated from the Go
  reference.
- **`impl/<library>-<minor>[-<adapter>]/`** — frozen implementation entries,
  each with a capability manifest (see `impl/README.md`). Entries are frozen
  per minor version, so the grid also tests **cross-version** conformance.
- **`orchestrator/`** — the matrix runner (containers + compose); derives the
  grid from the manifests.

## Status

Foundation. The contract, entry/manifest scheme, and scenarios are defined,
with `impl/go-0.12/` as the seed entry. Next: generate the fixture from
`valiss-go`, build the go-0.12 harness runnables, then the orchestrator.
Python joins as a client (and message verifier) with the spec-1 port, and as a
signed-request server once it ships the request verifier (allowlist + replay).
