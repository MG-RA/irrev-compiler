# Git Diff Scope Contract: `scope:git.diff@0`

Status date: 2026-02-07

## Purpose

`scope:git.diff@0` defines deterministic change witnesses between two commits so
review, policy, and projection layers can reason about changes without trusting UI diffs.

## v0 Scope Surface

- `git.diff.capture(input) -> git_diff_witness`

The v0 witness captures:
- `base_commit_oid`
- `head_commit_oid`
- normalized change list with:
  - `path`
  - `change_kind` (`added`, `modified`, `deleted`, `renamed`, `copied`, `type_changed`, `unmerged`, `unknown`)
  - optional old/new blob OIDs
  - optional additions/deletions counts

## Determinism

- Paths are normalized (`\` -> `/`, strip leading `./`) before ordering.
- Change entries are sorted and unique by `(path, change_kind)`.
- Add/delete invariants are validated (`added` requires `new_blob_oid`, `deleted` requires `old_blob_oid`).
- Witness bytes are canonical CBOR.
- Witness identity is `sha256(canonical_cbor(id_payload))` and excludes `created_at_utc` and metadata.

## Witness Contract

- Schema: `git-diff-witness/0`
- Canonical encoding: `canonical-cbor`
- Implemented in:
  - `crates/admit_core/src/git_operations.rs`
  - `crates/admit_core/src/git_witness.rs`

## Dependencies

- Canonical encoding: `scope:encode.canonical@0`
- Stable content identity: `scope:hash.content@0`
- Natural downstream pair: structural patch scopes (`scope:patch.plan@0`, future `scope:patch.apply@*`)

