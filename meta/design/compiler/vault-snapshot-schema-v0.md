# Vault Snapshot Schema v0

Status date: 2026-01-29

This schema defines the canonical JSON snapshot consumed by the Rust compiler. The
snapshot is content-addressed: **hashes are computed over canonical JSON bytes**.

## Schema identity

- `schema_id`: `vault-snapshot/0`
- `schema_version`: `0`

## Canonical JSON rules

1. UTF-8 encoding.
2. JSON objects are serialized with **lexicographically sorted keys**.
3. No extra whitespace (use `,` and `:` separators).
4. Strings use standard JSON escaping; non-ASCII is escaped (`ensure_ascii=True`).
5. Arrays are already **sorted deterministically** by the exporter (see ordering rules).

Hash = `sha256(canonical_json_bytes(snapshot))`.

## Top-level structure

```
{
  "schema_id": "vault-snapshot/0",
  "schema_version": 0,
  "concepts": [ ... ],
  "diagnostics": [ ... ],
  "domains": [ ... ],
  "projections": [ ... ],
  "papers": [ ... ],
  "meta": [ ... ],
  "support": [ ... ],
  "rulesets": [ ... ]
}
```

## Ordering rules (lists)

Each list is sorted by:

1. `name` (case-insensitive)
2. `path` (lexicographic, forward-slash)

`depends_on` and `aliases` are sorted case-insensitively and de-duplicated.

## Entry shapes

### Concept

```
{
  "name": "scope-change",
  "layer": "first-order",
  "role": "concept",
  "canonical": true,
  "aliases": ["scope change"],
  "depends_on": ["boundary-crossing", "irreversibility", ...],
  "path": "concepts/scope-change.md"
}
```

### Note (diagnostics/domains/projections/papers/meta/support)

```
{
  "name": "Explanatory Circuits",
  "role": "diagnostic",
  "canonical": false,
  "depends_on": ["admissibility", "erasure-cost", ...],
  "path": "diagnostics/Explanatory Circuits.md"
}
```

`depends_on` may be empty for note types where dependencies are not explicit.

### Ruleset

```
{
  "path": "meta/rulesets/core.toml",
  "sha256": "<content hash>"
}
```

## Exporter output

The Python exporter writes:

- `snapshot.json` (canonical JSON)
- `snapshot.json.sha256` (hash of canonical bytes)

The Rust compiler consumes `snapshot.json`, recomputes the canonical bytes, and
verifies the hash before use.

## Projection bridge

Snapshot v0 is the provenance anchor for ProgramBundle v0. Projection exporters
must include the snapshot hash in the ProgramBundle provenance so the compiler can
trace `.adm` generation back to a stable vault state.
