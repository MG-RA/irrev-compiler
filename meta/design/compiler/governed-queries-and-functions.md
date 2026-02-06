---
role: support
type: implementation-note
canonical: true
---

# Governed queries and functions (court artifacts)

This note defines a minimal pattern for storing queries and function definitions as governed, content-addressed artifacts.

Goal: make "what query ran" and "what function definition was in force" auditable and replayable, without making the database the authority.

## Court vs memory

- Court (authoritative): canonical CBOR bytes minted by Rust, stored in the artifact store, referenced by sha256.
- Memory (non-authoritative): SurrealDB tables that index and expose these artifacts for UI and retrieval.

SurrealDB may store and normalize values for querying, but it must not rewrite the canonical bytes that define identity.

## Artifact kinds (v0)

Two new artifact kinds are introduced:

- `query_artifact` with schema id `court-query/0`
- `fn_artifact` with schema id `court-function/0`

Both are encoded as canonical CBOR maps (RFC 8949 canonical form via `admit_core::cbor`).

### `court-query/0` fields

- `schema_id` (string, required)
- `schema_version` (u32, required, currently 0)
- `name` (string, required)
- `lang` (string, required, default `surql`)
- `source` (string, required)
- `tags` (array of strings, optional, stored sorted+deduped)

### `court-function/0` fields

Same shape as `court-query/0`, but represents a function definition rather than an ad-hoc query.

## Ledger events (v0)

Registration is recorded via ledger events:

- `court.query.registered`
- `court.function.registered`

Both events include:

- `timestamp`
- `artifact_kind` (`query` or `function`)
- `artifact` (an `ArtifactRef` pointing to the content-addressed CBOR artifact)

Optionally repeated for convenience:

- `name`, `lang`, `tags`

The ledger remains the authoritative history of "what was declared".

## SurrealDB projection tables (v0)

To support Surrealist and runtime inspection, two schemaless tables are projected:

- `query_artifact`
- `fn_artifact`

Each row is keyed by record id derived from the artifact sha256 and contains:

- `artifact_sha256`
- `schema_id`
- `name`
- `lang`
- `source`
- `tags`
- `created_at_utc`

These tables are projections only. The artifact store remains the canonical source of the bytes.

## CLI surface (current)

Register a query:

- `admit_cli court query add --name NAME --file PATH [--lang surql] [--tag TAG ...]`

Register a function definition:

- `admit_cli court function add --name NAME --file PATH [--lang surql] [--tag TAG ...]`

Both commands:

- store the canonical artifact in `out/artifacts/<kind>/<sha256>.cbor` (with a JSON view)
- optionally append a `court.*.registered` event to `out/ledger.jsonl`
- optionally project to SurrealDB when `--surrealdb-mode` enables projection

## Future extensions (choose later)

- Materialize a subset of `fn_artifact` definitions into SurrealDB schema via `DEFINE FUNCTION`.
  - This should be treated as an effectful mutation with plan/approval/witness requirements.
- Add an execution harness that runs queries/functions and emits a witness artifact for results.
- Add a lint rule: disallow running non-artifact queries in governed scopes unless they are explicitly "untracked experiments".

