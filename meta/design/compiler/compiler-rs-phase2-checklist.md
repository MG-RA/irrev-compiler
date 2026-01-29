# Phase 2 Checklist (.adm parser + lowering)

Status date: 2026-01-29
Applies to: `meta/design/compiler/compiler-rs-plan.md` Phase 2

## Erasure-cost-upfront requirements

- [x] Enforce `allow_erase` requires a matching `erasure_rule` during lowering
- [x] Validate `erasure_rule` includes bucket + unit
- [x] Reject conflicting permissions (`allow_erase` + `deny_erase`)
- [x] Require explicit dependencies and core `module:irrev_std@1`
- [x] Validate duplicate dependencies

## Parser + lowering improvements

- [x] Custom identifier lexer supports `:` and `@` (e.g., `difference:foo`, `module:irrev_std@1`)
- [x] Structured parse errors with spans (line/col + byte offsets)
- [x] Reserved namespace enforcement (invalid prefixes rejected in lowering)
- [x] Duplicate declaration detection (difference/transform/bucket/constraint)
- [x] Deterministic lowering order for declarations
- [x] Cross-module reference rejection (no `module:*` in local references)
- [x] Emit dependencies into IR (`Program.dependencies`)
- [x] Modularized `admit_dsl` and `admit_core` into focused submodules

## Tests + fixtures

- [x] Golden `.adm` fixture for a minimal valid program
- [x] Parse-error tests (invalid module decl)
- [x] Lowering error tests (missing dependency, invalid prefix, allow without rule)
- [x] Serde round-trip tests for `admit_core::Program` and `admit_dsl::Program`
