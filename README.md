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
- **`harness/<library>-<minor>[-<adapter><framework-major>]/`** — frozen
  implementation entries, each a thin server/client harness wrapping a pinned
  implementation version, with a capability manifest (see
  `harness/README.md`). Entries are frozen per minor version — and adapter
  entries per framework major — so the grid also tests **cross-version**
  conformance.
- **`orchestrator/`** — the matrix runner; derives the grid from the
  manifests and executes it (see `orchestrator/README.md`).

## Status

Operational. The contract, entry/manifest scheme, scenarios, fixture, the
`harness/go-0.12/` reference entry, and the orchestrator are in place. The
matrix runs locally with `go -C orchestrator run .` (process runner by
default; `--runner docker|podman|apple` for the container mode) and in CI
(`.github/workflows/matrix.yaml`, docker runner) on pushes to `main` and PRs.
Next: Python joins as a client (and message verifier) with the spec-1 port,
and as a signed-request server once it ships the request verifier
(allowlist + replay).
