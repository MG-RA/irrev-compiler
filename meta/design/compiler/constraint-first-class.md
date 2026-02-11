# Constraint First-Class (Compiler Design)

Status: planned, not yet implemented (as of 2026-02-11).

## Summary
Make constraints first-class compiler objects with stable IDs, attached metadata, and deterministic witness output. This removes the current "optional id" path and makes constraint declarations an explicit, addressable unit across parse, lower, evaluate, and witness emission.

This document is a target-state design note, not current behavior.

## Motivation
- Constraints are the core admissibility boundary, but today they are only partially structured.
- Optional IDs and tag side-channels make constraint identity and metadata brittle.
- Witness output should be able to reference a constraint deterministically and include its metadata.

## Current State (as of Feb 2026)
- DSL uses `constraint <name>` followed by `@inadmissible_if ...`.
- Lowering uses a pending constraint slot and emits:
  - `Stmt::Constraint { id: Option<SymbolRef>, expr, span }`
  - `Stmt::ConstraintMeta { id, key, value, span }`
- `Env` stores `Vec<(Option<SymbolRef>, BoolExpr, Span)>`.
- `Fact::ConstraintTriggered` includes `Option<SymbolRef>`.

Implementation note:
- Anonymous constraints are still accepted in code.
- This means witness facts may omit `constraint_id` today.
- Any references to "must" below are intended-state requirements.

## Goal
Constraints are a first-class entity with:
- A required, stable ID (no anonymous constraints).
- Inline metadata/tags as part of the declaration.
- Deterministic ordering and hashing.
- Explicit inclusion in the witness so any trigger is explainable without source context.

## Non-Goals
- Changing the logical meaning of constraints.
- Adding new predicate types or expression semantics.
- Replacing the existing lint/query system.

## Proposed Design
### 1) IR: Dedicated Constraint Declaration
Replace the split `Constraint` + `ConstraintMeta` with a single, explicit declaration:
- `ConstraintDecl { id: SymbolRef, expr: BoolExpr, tags: Vec<ConstraintTag>, span: Span }`
- `ConstraintTag { key: String, value: String }`

All constraints must have an ID. Tags are stored directly on the declaration and are sorted deterministically for hashing and output.

### 2) DSL: Explicit First-Class Constraint
Keep the current syntax but remove the anonymous path:
- `constraint <name>` MUST be followed by `@inadmissible_if`.
- `tag <k> <v>` remains valid only after `constraint`.
- The compiler rejects `@inadmissible_if` without an active constraint.

If desired later, add a single-line form:
- `constraint <name> inadmissible_if <expr>`

### 3) Lowering Rules
- Reject missing constraint IDs and duplicates.
- Move tags into the constraint declaration.
- Emit deterministic tag ordering (key, value) prior to building the constraint.

### 4) Env and Evaluation
- Store constraints in a deterministic map keyed by `SymbolRef`.
- Evaluation iterates in lexical order (BTreeMap) for deterministic traces.
- Triggered constraints always include ID.

### 5) Witness Changes
- Add a `constraints` section to the witness payload containing:
  - `id`, `expr` (or a canonical string), and `tags`.
- `Fact::ConstraintTriggered` MUST include `constraint_id`.
- Preserve deterministic ordering for both `constraints` and facts.

### 6) Determinism and Hashing
- Use BTreeMap/BTreeSet for constraint and tag ordering.
- Explicitly canonicalize tag order by `(key, value)`.
- Any hash or canonical CBOR encoding should include constraint declarations in a stable order.

## Compatibility and Migration
- Old programs with implicit/anonymous constraints should fail with a clear error.
- Provide a short migration note in user docs:
  - "Add `constraint <name>` before every `@inadmissible_if`."
- Consider a temporary feature flag to allow old behavior if needed.

## Implementation Plan (Compiler)
1) admit_core
   - Add `ConstraintDecl` and `ConstraintTag` types to IR.
   - Update `Env` and `constraints.rs` to use IDs only.
   - Update witness schema to include `constraints` list and required IDs in facts.

2) admit_dsl
   - Update lowering to build `ConstraintDecl` with tags.
   - Remove `ConstraintMeta` emission and support.
   - Update tests to expect errors on anonymous constraints.

3) admit_cli / outputs
   - Update any JSON projections to include constraints.
   - Ensure deterministic ordering in emission.

4) Docs
   - Update user docs and DSL examples to show explicit constraint declarations.

## Open Questions
- Should constraint IDs include an explicit namespace prefix in DSL (e.g., `constraint:foo`), or rely on current symbol rules?
- Should the witness include the full BoolExpr AST or a canonical string rendering?
- Do we need a schema bump for the witness format to add `constraints`?

## Appendix: Files Likely Touched
- `crates/admit_core/src/ir.rs`
- `crates/admit_core/src/env.rs`
- `crates/admit_core/src/constraints.rs`
- `crates/admit_core/src/witness.rs`
- `crates/admit_dsl/src/lowering.rs`
- `crates/admit_dsl/src/parser.rs`
- `crates/admit_dsl/src/tests.rs`
