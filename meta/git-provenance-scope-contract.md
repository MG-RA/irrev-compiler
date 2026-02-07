# Git Provenance Scope Contract: `scope:git.provenance@0`

Status date: 2026-02-07

## Purpose

`scope:git.provenance@0` binds artifact and registry evolution to commit history with
deterministic witnesses so governance can answer "who introduced what, and from which commit?"
without relying on mutable dashboards.

## v0 Scope Surface

- `git.provenance.capture(input) -> git_provenance_witness`

The v0 witness includes:
- repository identity (`repository_id`)
- optional base commit + required head commit
- artifact bindings: `(artifact_kind, artifact_sha256) -> commit_oid`
- registry bindings: `(entry_kind, entry_id, entry_version) -> introduced_in_commit_oid`
- signature attestations per commit (`verified`, `unverified`, `unknown`)

## Determinism

- Artifact bindings are sorted/unique by `(artifact_kind, artifact_sha256, commit_oid)`.
- Registry bindings are sorted/unique by
  `(entry_kind, entry_id, entry_version, introduced_in_commit_oid)`.
- Signature attestations are sorted/unique by `commit_oid`.
- Witness bytes use canonical CBOR.
- Witness identity is `sha256(canonical_cbor(id_payload))` and excludes `created_at_utc` + metadata.

## Witness Contract

- Schema: `git-provenance-witness/0`
- Canonical encoding: `canonical-cbor`
- Implemented in:
  - `crates/admit_core/src/git_operations.rs`
  - `crates/admit_core/src/git_witness.rs`

## Dependencies

- Canonical encoding: `scope:encode.canonical@0`
- Stable content identity: `scope:hash.content@0`
- Complementary scopes:
  - `scope:git.snapshot@0`
  - `scope:git.diff@0`

