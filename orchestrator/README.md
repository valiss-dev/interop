# orchestrator

The matrix runner. For each `transport`, starts each `server_lang` harness with
the frozen fixture, then runs every `scenarios.yaml` scenario through each
`client_lang` harness against it, comparing the client's reported outcome to the
scenario's `expect`. A cell `(server × client × transport)` passes when all its
scenarios pass; the matrix passes when all cells do.

Implementations run as containers (one image per impl), so the orchestrator
needs no per-language toolchain. See `../CONTRACT.md`.
