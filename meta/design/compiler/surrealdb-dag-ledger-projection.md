---
role: support
type: design-note
canonical: true
facets:
  - surrealdb
  - runtime
  - projection
status_date: 2026-02-05
---

# SurrealDB Projection: Governed DAG + Ledger (v0)

This note specifies a SurrealDB-backed **projection/index** for:

- `scope:db:dag` (graph traversal over governed nodes/edges)
- `scope:db:ledger` (append-only event stream for replay/audits/time windows)

Authoritative identity remains in Rust:

- canonical CBOR bytes
- `sha256(canonical_bytes)` as identity
- admissibility checks and hard invariants enforced before writes

SurrealDB is used for storage, indexing, traversal, and change notification — not for “proving” admissibility.

## Deployment shapes

1. **Projection-first (recommended v0)**
   - file-backed artifacts + ledger remain authoritative
   - SurrealDB can be rebuilt from the ledger and trace artifacts
2. **Primary-store (later)**
   - SurrealDB stores canonical blobs and enforces append-only constraints via policy
   - requires explicit durability/crash/replay tests

## Record IDs

Use stable record IDs to make upserts cheap and deterministic:

- `node:<node_id_hex>`
- `artifact:<sha256_hex>`
- `dag_trace:<trace_sha256_hex>`
- `ledger_event:<event_id>`

## Tables (conceptual)

### `artifact`

Fields (suggested):

- `hash` (string; sha256 hex)
- `kind` (string)
- `schema_id` (string)
- `size_bytes` (number)
- `bytes_ref` (string? file path or URI; optional in projection-first)
- `created_at` (datetime; optional metadata)

### `node`

Fields (suggested):

- `node_id` (string; same as record id suffix)
- `kind` (object or string tag)
- `category` (string)
- `scope_id` (string)
- `artifact_hash` (string? sha256; if present)
- `metadata` (object? non-identity hints)
- `created_at` (datetime? optional)

### `edge` (relation)

Represent edges as first-class relation records with properties.

Fields (suggested):

- `edge_type` (string)
- `scope_id` (string)
- `timeline` (string)
- `seq` (number)
- `witness_ref` (string? node id)
- `metadata` (object? optional)

### `dag_trace`

Store trace identity + optional canonical bytes reference:

- `trace_sha256` (string)
- `timeline` (string)
- `produced_by` (string; e.g. `admit-cli`)
- `authority_state_hash` (string? if available)
- `bytes_ref` (string? file path)

### `ledger_event`

Projection of ledger events for time queries/replay:

- `event_id` (string)
- `kind` (string)
- `ts` (datetime)
- `timeline` (string)
- `seq` (number)
- `payload_hash` (string? artifact hash)
- `authority_state_hash` (string?)
- `plan_hash` (string?)

Append-only policy: treat updates as new events (or disallow updates at the interface).

## SurrealQL sketch

### Upsert node

```sql
UPDATE node:$node_id CONTENT {
  node_id: $node_id,
  kind: $kind,
  category: $category,
  scope_id: $scope_id,
  artifact_hash: $artifact_hash,
  metadata: $metadata
};
```

### Upsert artifact index

```sql
UPDATE artifact:$hash CONTENT {
  hash: $hash,
  kind: $kind,
  schema_id: $schema_id,
  size_bytes: $size_bytes,
  bytes_ref: $bytes_ref
};
```

### Insert edge relation

```sql
RELATE node:$from->edge->$to SET
  edge_type = $edge_type,
  scope_id = $scope_id,
  timeline = $timeline,
  seq = $seq,
  witness_ref = $witness_ref;
```

If you need idempotency, use a deterministic edge record id such as:

- `edge:<from>:<to>:<timeline>:<seq>:<edge_type>`

and `UPDATE edge:<id> ...; RELATE ...` using that id.

### Append ledger event

```sql
CREATE ledger_event:$event_id CONTENT {
  event_id: $event_id,
  kind: $kind,
  ts: $ts,
  timeline: $timeline,
  seq: $seq,
  payload_hash: $payload_hash,
  authority_state_hash: $authority_state_hash,
  plan_hash: $plan_hash
};
```

## Query examples (what this enables)

- Authority reachability: traverse `AuthorityDepends` edges from `AuthorityRoot` nodes to effectful nodes.
- “What depends on this?”: reverse traversal over `BuildDepends`.
- “Witness bundle for mutation”: follow `WitnessOf` edges into the target node, then expand to referenced artifacts.
- Time-window audits: `SELECT * FROM ledger_event WHERE ts > ... ORDER BY timeline, seq`.

## Change feeds / live queries (runtime loop driver)

Continuous mode can subscribe to:

- new `ledger_event` rows in specific kinds (e.g. `plan.created`, `approval.granted`)
- new `dag_trace` rows

Each change triggers a `tick(...)` command; the tick remains the authoritative adjudication step.

## Related

- `meta/DAG.md`
- `meta/design/compiler/runtime-genesis-implementation-plan.md`
- `meta/Boundary Events & DB Scope.md`
