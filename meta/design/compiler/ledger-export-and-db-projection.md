# Ledger Export + DB Projection (Log as authority, DB as view)

Status date: 2026-01-31

## Goal

Keep the kernel ledger as the authoritative append-only log, while enabling fast queries and multi-machine workflows via rebuildable DB projections.

Core invariant:

> DB may accelerate queries, but it must not be required to decide admissibility verdicts.

Verdicts depend on: canonical log + witness blobs + registry core. DB is a disposable index/view.

## Model: log vs index

- **Kernel ledger (log):** append-only, content-addressed references, chain integrity, minimal semantics.
- **DB projection (index/view):** denormalized tables/edges, fast queries, dashboards; rebuildable from log+blobs.

## Step 0 — Event identity + sequencing (minimum for idempotent ingestion)

To make projection ingestion simple and idempotent, every ledger event needs:

- `seq` (u64, monotonic; total order in this ledger)
- `event_id` (content hash of canonical event bytes)
- `prev_event_id` (optional for seq=0; required otherwise)
- `chain_hash` (optional but recommended: hash(prev_chain_hash || event_id) or equivalent)

Additional recommended fields (already mostly present in current events):

- `event_type` (string)
- `timestamp` (ISO-8601 string; treat as informational unless attested)
- `scope_id` (string; `scope:domain.scope` naming)
- `schema_id` (string; identifies the payload schema, if a payload object exists)
- `refs[]` (typed references to artifacts / other events)
- `payload_hash` (hash of the payload bytes if payload is stored as a blob)

Rule: `event_id` must be computed from canonical bytes that include `seq` and `prev_event_id` so the chain is unambiguous.

## Step 1 — Export stream format (stable ingestion boundary)

Define an export stream so sinks do not need to know the on-disk folder layout.

### Command shape

- `admit-cli ledger export --from <seq> --to <seq> --format jsonl|cbor`

### JSONL export (human/debug friendly)

One event per line, where each line is the canonical JSON encoding of:

```json
{
  "seq": 123,
  "event_id": "<sha256 hex>",
  "prev_event_id": "<sha256 hex>",
  "chain_hash": "<sha256 hex>",
  "event_type": "admissibility.checked",
  "timestamp": "2026-01-31T12:34:56Z",
  "scope_id": "scope:ledger.append",
  "refs": [
    { "kind": "artifact", "schema_id": "admissibility-witness/1", "sha256": "<...>", "size_bytes": 1234 }
  ],
  "payload": { "...": "optional small inline payload" },
  "payload_hash": "<sha256 hex>"
}
```

Notes:

- Canonical JSON must be deterministic (sorted object keys, stable arrays).
- Prefer `payload_hash` + artifact refs over embedding large payloads.

### CBOR export (transport/stability friendly)

CBOR sequence of events using the same logical structure. Requirements:

- canonical CBOR encoding (same rules as witness CBOR)
- stable field names/ordering via canonicalization

Framing options:

- indefinite-length CBOR array of event objects, or
- length-delimited CBOR objects (preferred if streaming)

## Step 2 — DB projection sink (as governed effect)

Model “push ledger to DB” as an effect scope:

- Domain: `ledger`
- Scope: `ledger.project.db` (or `db.ingest.ledger`)

It consumes:

- exported event stream (from the canonical log)
- artifact refs (optional resolution for extra metadata)
- registry hash (to bind schema/scope meaning at ingestion time)

It emits witnesses:

- `ledger-projection-updated/0`
- `ledger-projection-drift/0`

## Minimal DB tables (generic; works for SurrealDB/SQLite/Postgres)

- `events(seq primary key, event_id unique, prev_event_id, chain_hash, ts, event_type, scope_id, payload_hash, registry_hash)`
- `artifact_refs(event_id, seq, kind, schema_id, sha256, size_bytes, path?)`
- `event_refs(event_id, seq, ref_event_id, kind)` (optional)
- `schema_refs(schema_id, first_seq, last_seq)` (optional rollups)
- `scope_refs(scope_id, first_seq, last_seq)` (optional rollups)

Ingestion rules:

- upsert by `event_id` (idempotent)
- ensure `seq` monotonicity and chain linkage matches exported stream
- store “last ingested seq” as sink state

## Projection witnesses (schemas)

### `ledger-projection-updated/0`

Minimum fields:

- `schema_id: "ledger-projection-updated/0"`
- `db_id` (dsn hash or named sink id)
- `projection_version`
- `from_seq`, `to_seq`
- `registry_hash` (the registry artifact hash used during ingestion)
- `source_ledger_hash` (optional: chain_hash at `to_seq`)

### `ledger-projection-drift/0`

Emitted when the sink detects inconsistency:

- `schema_id: "ledger-projection-drift/0"`
- `db_id`
- `expected_from_seq` / `expected_prev_event_id`
- `observed_seq` / `observed_prev_event_id`
- `registry_hash`
- `reason` (short, structured)

## Non-goals (for v0)

- Making DB the source of truth for admissibility.
- Requiring network access for core verdicts.
- Complex replication semantics; the export stream is the portability layer.

