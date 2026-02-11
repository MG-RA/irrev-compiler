# CLI Ceremony Protocol (Normative)

Version: 0.1  
Status date: 2026-02-11

## Scope

This spec defines binding CLI ceremony for admissibility-related effects.

## Primary Chain

The canonical chain is:

1. `declare-cost`
2. `check`
3. `execute`

Normative requirements:

1. `declare-cost` MUST bind witness hash, snapshot hash, and program reference.
2. `check` MUST validate the declared event and artifact hashes before emitting `admissibility.checked`.
3. `execute` MUST require a prior checked event id and MUST re-verify referenced hashes before emitting `admissibility.executed`.

## Binding Rules

## C-010 - Ledger-bound identities

`event_id` values MUST be derived from canonical payload bytes and re-checkable during verification.

Enforced by:

- `crates/admit_cli/src/witness.rs` (`payload_hash` checks)
- `crates/admit_cli/src/verify.rs`

## C-020 - No execute without checked event

Execute MUST fail if the referenced checked event is missing or invalid.

Enforced by:

- `crates/admit_cli/src/witness.rs` (`execute_checked`)

## C-030 - Registry-aware artifact admission

When a meta registry is present, artifact schema ids and scope ids MUST be registry-valid.

Enforced by:

- `crates/admit_cli/src/artifact.rs`
- `crates/admit_cli/src/registry.rs`
- `crates/admit_cli/src/verify.rs`

## C-040 - Append-only event discipline

Ledger writes SHALL be append-only and duplicate event ids MUST be rejected.

Enforced by:

- `crates/admit_cli/src/ledger.rs`
- `crates/admit_cli/src/rust_ir_lint.rs` (duplicate guard on append path)

## Effect Classes

This protocol applies strictly to irreversible execute/apply operations.
Observation-oriented commands may emit witnesses and artifacts without passing through execute, but MUST remain verifiable and content-addressed.

## Outstanding Gap

ProviderRegistry wiring into actual CLI evaluator call sites remains a tracked gap (`F-03`), because current CLI surfaces do not yet route `eval_with_provider` end to end.

