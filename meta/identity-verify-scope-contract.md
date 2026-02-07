# Identity Verify Scope Contract: `scope:identity.verify@0`

Status date: 2026-02-07

## Purpose

`scope:identity.verify@0` validates delegation and attestation records produced by
identity-related scopes. It is the verification boundary for delegated authority.

## v0 Scope Surface

- `identity.verify.delegation(record, context) -> verification_result`
- `identity.verify.attestation(record, context) -> verification_result`

## Verification Requirements (v0)

- Canonical payload integrity check (deterministic bytes).
- Identity hash consistency check.
- Scope allowance check (`context.required_scope` must be delegated).
- Temporal validity check (`issued_at_utc`, `expires_at_utc`).
- Revocation check when a revocation record exists.

## Determinism

- Verification output is deterministic for identical record + context.
- Uses `scope:hash.verify@0` and `scope:identity.delegate@0` semantics.

## Notes

This v0 contract does not prescribe cryptographic key infrastructure details.
It defines the verifiable interface and decision rules required for governance.

