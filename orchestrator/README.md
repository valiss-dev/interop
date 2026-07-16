# orchestrator

The matrix runner (CONTRACT.md). It discovers the entries under `harness/`
by manifest, derives the `(server × client × transport)` grid with the
pairing and gating rules, executes every applicable `scenarios.yaml` scenario
in each cell, judges the client-reported outcomes, and reports the matrix.
Cells without a shared spec version are recorded incompatible; scenarios
gated off by a missing server capability are reported skipped. The exit code
is nonzero iff an applicable scenario failed.

## Running

The orchestrator is its own Go module; run it from this directory (or from
the repo root with `go -C orchestrator run .` — the repo root is found via
`scenarios.yaml`, or pass `--root`):

```
go run . [--runner docker|podman|apple] [--report out.json]
         [--only-transport http|grpc] [--only-cell server:client]
         [--root DIR] [--scenarios FILE] [--harness-dir DIR] [--fixture-dir DIR]
```

Runners (all container-based; entries are language-agnostic images):

- `docker` (default) / `podman` — one image per entry (`build.dockerfile`),
  servers and clients joined on a per-run bridge network, the fixture
  bind-mounted read-only at `/fixture`.
- `apple` — the same mode on Apple's `container` CLI (macOS); containers
  reach each other by their vmnet IP. Needs `container system start`.

Container runners invoke the entry runnables by absolute path
(`/usr/local/bin/<id>-server`, `/usr/local/bin/<id>-client`), the convention
the entry Dockerfiles install to — entry images may be distroless with no
shell.

## Layout

- `internal/suite` — manifest/scenario schemas and the grid derivation.
- `internal/runner` — the `Runner` interface and its implementations.
- `internal/matrix` — cell execution, outcome judging, report rendering.
