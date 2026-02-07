# Git Snapshot Scope Contract: `scope:git.snapshot@0`

Status date: 2026-02-07

## Purpose

`scope:git.snapshot@0` defines deterministic repository-state snapshots suitable for
admissibility checks, reproducibility gates, and evidence-grade provenance.

## v0 Scope Surface

- `git.snapshot.capture(input) -> git_snapshot_witness`

The v0 witness captures:
- `head_commit_oid`
- `is_clean`
- tracked file list (`path`, `blob_oid`)
- optional submodule states (`path`, `commit_oid`)
- optional `working_tree_manifest_sha256`

## Determinism

- Paths are normalized (`\` -> `/`, strip leading `./`) before ordering.
- Tracked files and submodules are sorted and unique by path.
- Witness bytes are canonical CBOR.
- Witness identity is `sha256(canonical_cbor(id_payload))` and excludes `created_at_utc` and metadata.

## Witness Contract

- Schema: `git-snapshot-witness/0`
- Canonical encoding: `canonical-cbor`
- Implemented in:
  - `crates/admit_core/src/git_operations.rs`
  - `crates/admit_core/src/git_witness.rs`

## Dependencies

- Canonical encoding: `scope:encode.canonical@0`
- Stable content identity: `scope:hash.content@0`

