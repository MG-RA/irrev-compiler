# Adjudicator Transition (V2)

## Intent
Move the runtime from implicit ruleset drift to explicit, witnessed lens evolution.

This transition keeps core invariants:
- append-only ledger
- witness-first evidence model
- default-deny erasure
- explicit boundary/meta changes

## Runtime Additions
- `Lens` as a declared, versioned object (`lens_id`, `lens_hash`)
- explicit `lens.activated` ledger event
- `MetaChange` as a first-class IR statement
- `Query::InterpretationDelta` for two-lens comparison
- `lens-delta-witness/0` artifact schema

## Wire Cutover
- writer default schema: `admissibility-witness/2`
- registry schema: `meta-registry/1`
- lens delta schema: `lens-delta-witness/0`

`admissibility-witness/2` requires lens metadata on each witness payload:
- `lens_id`
- `lens_hash`
- `lens_activation_event_id`

## Governance Model
- `to_lens_hash` is kernel-derived from `(from_lens_hash, kind, payload_ref)`
- meta-change displacement is attached to a synthetic diff id:
  `difference:lens_change:<from_hash>-><to_hash>:<kind>`
- registry includes:
  - `default_lens`
  - `lenses[]`
  - `meta_change_kinds[]` capability declarations
  - `meta_buckets[]` (including core epistemic buckets)

## Migration
- `admit registry migrate-v0-v1 --input ... --out ...`
- deterministic migration injects:
  - default lens declaration
  - core meta buckets (`trust_debt`, `compatibility_debt`, `explanation_debt`)
  - empty/seeded meta-change kind catalog

## Current Slice
This implementation includes the vertical path needed to enforce explicit lens activation in check/eval flows and to ledger lens lifecycle events, while preserving legacy registry read compatibility.

## Implementation State (2026-02-14)
Completed:
- `admissibility-witness/2` default writer path is active.
- Lens metadata (`lens_id`, `lens_hash`, `lens_activation_event_id`) is propagated through check/execute flows for v2 witnesses.
- `lens.activated` events are emitted in check and ruleset-check flows.
- Ruleset-check default ledger isolation now uses `<artifacts_dir>/ledger.jsonl` when `--ledger` is not provided.
- `MetaChange` and `InterpretationDelta` IR/DSL surfaces are present.
- `admit lens delta` emits deterministic `lens-delta-witness/0` artifacts.
- `admit lens delta` appends `meta.interpretation.delta` ledger events.
- `admit lens update` appends `meta.change.checked` ledger events.
- `admit lens update` enforces governed admission checks:
  - registry-required lens and kind resolution
  - capability flags gated by `meta_change_kinds[]`
  - explicit route parsing and bucket validation
  - `requires_manual_approval` enforcement
  - kernel-derived `to_lens_hash` with optional `to_lens` binding verification
  - deterministic synthetic diff ID format
- `meta-registry/1` shape and `admit registry migrate-v0-v1` are implemented.
- Golden witness fixtures and registry hash pin were updated to current V2 canonical outputs.
- Canonical hash pins are enforced in tests for:
  - `meta-registry/1` sample (from `registry init`)
  - default lens v0 canonical bytes
  - `admissibility-witness/2` sample
  - `lens-delta-witness/0` sample
- Integration lineage test covers append-only sequencing:
  - ruleset `check` (with lens activation)
  - `lens delta` append
  - `lens update` append
  - immutable prefix checks across ledger growth

Compatibility behavior:
- Legacy `admissibility-witness/1` remains accepted.
- Ledger verification enforces lens activation linkage only for `admissibility-witness/2`.
- Registry loading accepts both `meta-registry/0` and `meta-registry/1`.

Remaining (outside V2 core):
- Optional UX/docs expansion for v3 CI flows (`CIv3.md`) and automation commands.

Validation state:
- `cargo test -p admit_core -p admit_dsl -p admit_cli --no-fail-fast` passes.
