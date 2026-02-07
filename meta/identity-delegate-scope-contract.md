# Identity Delegate Scope Contract: `scope:identity.delegate@0`

Status date: 2026-02-07

## Purpose

`scope:identity.delegate@0` governs deterministic capability delegation records.
It defines how an actor grants scoped authority to another actor with explicit limits.

## v0 Scope Surface

- `delegate.issue(payload) -> delegation_record`
- `delegate.revoke(record_id) -> revocation_record`

Both records are content-addressed, canonical-encoded artifacts and intended to be
verifiable offline.

## Required Payload Fields (v0)

- `issuer_id`
- `delegate_id`
- `scope_ids` (allowed scopes)
- `constraints` (time/risk/operation limits)
- `issued_at_utc`
- `expires_at_utc` (optional)

## Determinism

- Canonical encoding: `scope:encode.canonical@0`
- Digest identity: `scope:hash.content@0`
- Record identity is hash of canonical payload bytes.

## Notes

This contract establishes the foundational interface and invariants for delegation.
Runtime signing/key management mechanisms are intentionally deferred to later versions.

