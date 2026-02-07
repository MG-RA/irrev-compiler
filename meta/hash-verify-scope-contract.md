# Hash Verify Scope Contract: `scope:hash.verify@0`

Status date: 2026-02-07

## Purpose

`scope:hash.verify@0` is the verification-facing sibling of `scope:hash.content@0`.
It governs deterministic digest checks for immutable byte inputs.

## Operation Surface

`verify(data: bytes, expected_digest: sha256_hex_lowercase) -> HashWitness`

Implementation lives in:
- `crates/admit_core/src/hash_operations.rs` (`verify`)
- `crates/admit_core/src/hash_witness.rs` (`HashWitness`, validation, witness id)

## Determinism and Safety

- Deterministic SHA-256 digest over provided bytes.
- Constant-time comparison is used for equality checks.
- Witness is emitted even on mismatch; admissibility logic decides pass/fail.
- Expected digest must be lowercase 64-char hex.

## Witness Contract

- Emits `hash-witness/0`.
- Uses canonical CBOR witness encoding and stable witness-id rules already pinned for hash witnesses.
- Compatible with existing hash witness integration tests.

## Dependencies

- Depends on `scope:hash.content@0` for aligned digest semantics.
- Uses canonical CBOR witness identity conventions from `scope:encode.canonical@0`.

