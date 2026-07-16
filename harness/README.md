# harness

Flat list of **frozen implementation entries** — each a thin server/client
harness wrapping a pinned implementation version (the implementations
themselves live in their own repos). One directory per
`(library, minor version[, adapter])`:

```
harness/
├── go-0.12/             core Go harness, 0.12.x series
├── go-0.13/             core Go harness, 0.13.x series
├── py-0.8/              core Python harness (joins with the spec-1 port)
└── py-0.8-django5/      Django adapter harness (server-only, HTTP, Django 5.x)
```

The directory name is only an ID —
`<library>-<MAJOR.MINOR[rcN]>[-<adapter><FRAMEWORK_MAJOR>]`, must equal the
manifest `id`. The `rcN` tag is glued to the version so it can never be
confused with an adapter segment. **Adapter entries always carry the framework
major they target** (`django5`, `echo4`): a framework major is a distinct
integration surface, and encoding it from day one keeps the ID stable when a
second major appears (`go-0.14-echo4` alongside `go-0.14-echo5`). Framework
minor/patch stay in the lockfile, like the library patch.

**Granularity is the minor version.** Wire conformance is a property of a
minor series: patch releases must not change the wire, so an entry pins the
series and its lockfile tracks an exact patch, which may be bumped within the
entry. The minor version is immutable — a new minor (or a new RC) is a **new
entry**, and old entries stay in the matrix. That is what makes the matrix
test **cross-version** conformance: every frozen entry keeps being paired
against every newer one, and a patch that does change the wire shows up as a
matrix failure. RC entries are the exception to retention: an RC entry gates
the release it precedes and is superseded by that release's entry — same
minor series, same wire surface, so there is no cross-version pair to keep.
Cutting an RC at all is a judgment call pre-1.0 (ADR 0013): wire-touching
changes warrant one; purely additive releases may skip straight to a stable
entry.

**What an entry can do lives in its `manifest.yaml`**, per role: which
transports it serves, which it can call, which modes and verifier features it
supports. The orchestrator discovers entries by manifest and pairs
capabilities — a server-only HTTP entry (e.g. Django) is automatically tested
by every entry that declares an HTTP client, and vice versa.

## Manifest schema

```yaml
id: py-0.8-django5            # must equal the directory name
library: valiss-py            # source repository in valiss-dev
adapter: django               # optional; absent for core entries
adapter_version: "5"          # framework major the glue targets; exact pin in the lockfile
version: "0.8"                # minor series (or e.g. "0.13rc1"); exact patch is in the lockfile
spec: [1]                     # wire spec versions implemented ([] = pre-spec legacy)

# Roles are optional: declare only what the entry provides.
server:
  transports: [http]          # http | grpc
  modes: [signed]             # signed-request and/or message-token
  features:                   # verifier capabilities (gate scenarios)
    allowlist: true           #   revocation via allowlist
    replay: true              #   nonce replay suppression
    epoch: true
    bearer: true
client:
  transports: [http, grpc]
  modes: [signed, message]

issue: [user, message]        # informative: levels the library can mint
build:
  dockerfile: Dockerfile      # builds one image providing the declared runnables
```

## Pairing and gating (what the orchestrator derives)

- For each transport `T`: every entry `S` with `server.transports ∋ T` pairs
  with every entry `C` with `client.transports ∋ T` → cell `(S × C × T)`.
- If `S.spec ∩ C.spec` is empty the cell is recorded **incompatible** — an
  expected outcome, not a failure. This is the cross-version story: a legacy
  pre-spec entry against a spec-1 entry documents the boundary.
- A scenario runs in a cell when its `mode` is in both sides' `modes` for
  their role and every capability in its `requires` is true in
  `S.server.features`. Scenarios skipped by capability are reported, not
  failed.
- A cell passes when every applicable scenario passes.