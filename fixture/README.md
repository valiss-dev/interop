# fixture

Frozen interop material — pinned operator key, allowlist, and creds files —
generated once from the Go reference (`valiss-dev/valiss-go`) and committed. It
is authoritative for every implementation's harness. See `../CONTRACT.md`.

`gen/` will hold the Go generator; its output (`operator.pub`, `allowlist.txt`,
`creds/*.creds`, `payloads/*`) is committed so harnesses need no minting step.
