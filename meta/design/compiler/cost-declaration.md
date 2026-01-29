# Cost Declaration Protocol (Phase 4)

Status date: 2026-01-29

This note defines the minimal Phase 4 contract: a `cost.declared` event that
irreversibly binds a witness identity to a program + snapshot context. The intent
is structural: no action is admissible without a prior, immutable cost declaration.

## Core invariant

A `cost.declared` record exists that binds `(program, snapshot_hash, witness_hash)`
to canonical witness bytes.

This record is append-only and never overwritten.

## Verifier rule (mechanized)

`sha256(canonical_cbor(witness_json)) == witness_sha256`

Canonical CBOR uses RFC 8949 rules (integer-only policy, no NaN/Inf). The witness
hash is computed over the canonical CBOR bytes, not over JSON.

## Minimal event envelope (v0)

Fields required for v0:

- `event_type: "cost.declared"`
- `event_id` (content-derived)
- `timestamp`
- `witness`
  - `schema_id`
  - `sha256`
  - `cbor_bytes` (or an artifact reference)
- `compiler`
  - `build_id`
- `snapshot_hash`
- `program_ref` (module + scope identifiers)

Optional mirrors:

- `displacement_trace_summary` (non-authoritative; witness remains source of truth)

## Non-claims

- The record is not a recommendation.
- The record does not assert that the action is good or bad.
- The record does not replace the witness; it pins the witness identity.

## Phase 4 P0 behavior

1. Verify witness identity with the verifier rule.
2. Reject on hash mismatch or missing witness identity inputs.
3. Emit append-only `cost.declared` record.

The command surface can be minimal (`declare-cost` only); additional commands
(`check`, `execute`) are deferred until later phases.

## CLI usage (current)

Example declarations:

```
cargo run -p admit_cli -- declare-cost \
  --witness-json execution/compiler-rs/testdata/golden-witness/allow-erasure-trigger.json \
  --witness-sha256 <sha256> \
  --compiler-build-id <build-id> \
  --snapshot <snapshot.json>
```

Example witness verification:

```
cargo run -p admit_cli -- witness-verify \
  --witness-json execution/compiler-rs/testdata/golden-witness/allow-erasure-trigger.json \
  --expected-sha256 <sha256> \
  --out-cbor out/witness.cbor
```

Example check (verifies a prior declaration and appends a checked event):

```
cargo run -p admit_cli -- check \
  --event-id <cost-declared-event-id> \
  --compiler-build-id <build-id>
```

Example check with facts bundle context:

```
cargo run -p admit_cli -- check \
  --event-id <cost-declared-event-id> \
  --facts-bundle <facts-bundle.json> \
  --compiler-build-id <build-id>
```

Example execute (requires a prior checked event):

```
cargo run -p admit_cli -- execute \
  --checked-event-id <admissibility-checked-event-id> \
  --compiler-build-id <build-id>
```

Example ledger verification:

```
cargo run -p admit_cli -- verify-ledger \
  --ledger out/ledger.jsonl
```

JSON output and dry-run flags:

```
cargo run -p admit_cli -- declare-cost --json --dry-run ...
cargo run -p admit_cli -- check --json --dry-run ...
cargo run -p admit_cli -- execute --json --dry-run ...
cargo run -p admit_cli -- verify-ledger --json ...
```

## Related

- `meta/design/compiler/semantics-instrumentation-ritual-binding.md`
