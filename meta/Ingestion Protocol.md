# Ingestion Protocol (v0)

Ingestion is the front door of the system. This protocol makes ingestion a first-class, queryable, content-addressed run, with explicit coverage and blind spots.

## Goals

- Ingestion always produces stable handles (content-addressed artifacts and ledger events).
- "What was ingested?" is answerable without relying on SurrealDB.
- Coverage and blind spots are explicit outputs, not implicit behavior.
- SurrealDB is a projection and query substrate, not the authority for identity.

## Court vs Memory

- Court (authoritative):
  - Artifact store: `out/artifacts/` (content-addressed).
  - Ledger: `out/ledger.jsonl` (append-only event stream).
- Memory (non-authoritative):
  - SurrealDB projections for querying, UI, and runtime triggers.

The authoritative identity bytes are minted in Rust and stored verbatim. SurrealDB stores projections and indexes only.

## Ingestion as a run

Each `ingest dir` invocation produces:

- `ingest.run.started` (ledger event)
- `ingest.run.completed` (ledger event; status is `complete` or `failed`)
- `ingest_config` artifact (`ingest-dir-config/0`)
- `ingest_coverage` artifact (`ingest-coverage/0`)
- `ingest_run` artifact (`ingest-run/0`)

The artifacts are canonical CBOR (identity) with a JSON projection for inspection.

## Phase separation (protocol-level)

This is the conceptual separation the runtime will enforce more strictly over time:

1) Acquire (effects allowed)
   - Read bytes from the filesystem (or other sources in the future).
2) Normalize (pure, deterministic)
   - Canonicalize paths, chunk markdown, extract frontmatter.
3) Derive (pure)
   - Build derived structures (DAG trace, doc index, link graph, etc.).

Today, `ingest dir` does "Acquire + Normalize" and produces snapshot/parse artifacts plus coverage and run records. Projections are separate steps.

## Coverage and blind spots

Ingestion emits an `ingest-coverage/0` artifact which includes:

- walk mode (`git_ls_files` or `fs_walk`)
- count of files/chunks ingested
- total bytes ingested
- skip-dir counters (hard-coded safety membrane: `.git`, `target`, `out`, etc.)
- warnings (blind spots), grouped by kind:
  - walk errors
  - read errors
  - non-utf8 paths
  - non-utf8 markdown (chunking skipped)

The purpose is not "no warnings". The purpose is: the system is forced to admit what it could not see.

## SurrealDB projection

When SurrealDB projection is enabled, ingestion events and run records are projected into:

- `ingest_run`
- `ingest_event`

These are queryable views for debugging / UI. They must not be used as the source of truth for identity or admissibility.

## CLI notes

- Correct workspace package name is `admit_cli`:
  - `cargo run -p admit_cli -- ingest dir .`
- `admit_cli.exe` can be used directly:
  - `target/debug/admit_cli.exe ingest dir .`

