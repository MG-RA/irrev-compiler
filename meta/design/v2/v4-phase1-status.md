# Irrev-Compiler v4 Phase 1 State (2026-02-14)

## Status
Phase 1 (provider contracts + scope-pack registry linking) is implemented and passing tests.

## Implemented
1. Typed provider predicate contract in `admit_core`:
- `PredicateDescriptor` includes `predicate_id`, `result_kind`, `emits_findings`, optional `evidence_schema`.
- `PredicateEvalContext` added with `facts`, `snapshot_hash`, `facts_schema_id`.
- `Provider::eval_predicate` now receives `(name, params, ctx)`.

2. Provider pack identity hashing:
- `provider_pack_hash(desc)` added in `crates/admit_core/src/provider_types.rs`.
- Hash uses normalized canonical CBOR over identity fields.
- `doc` text excluded from hash identity.

3. Rules engine context wiring + compatibility window:
- `evaluate_ruleset_with_inputs` builds `PredicateEvalContext` from input bundles.
- Legacy compatibility maintained by injecting `facts`, `snapshot_hash`, `facts_schema_id` into params when inputs are present.

4. Provider migration complete for current ruleset providers:
- `git.working_tree`, `deps.manifest`, `github.ceremony`, `rust.structure`, `text.metrics` use context-first facts lookup with legacy `params.facts` fallback.
- `ingest.dir` updated for descriptor/signature compatibility.

5. Meta-registry scope-pack model + normalization:
- `MetaRegistryV1.scope_packs` and `MetaRegistryScopePack` added.
- Normalization validates hash format, validates predicate ID uniqueness, sorts deterministically.
- Scope-pack duplicates are deduped if identical; conflicting duplicates are rejected.

6. Runtime linking and gate behavior:
- Ruleset check and CI compute runtime provider pack hashes and compare against registry `scope_packs`.
- Gate modes supported: `warn` (default) and `error`.
- Warning facts emitted in warn mode:
  - `provider/scope_pack_missing`
  - `provider/scope_pack_mismatch`

7. Registry sync command:
- Added `admit registry scope-pack-sync --input <path> --out <path>`.
- Command upserts built-in provider scope-pack entries, normalizes output, increments `registry_version`.

8. Documentation and tests:
- Provider protocol doc updated in `docs/spec/provider-protocol.md`.
- Added/updated tests across `admit_core`, `admit_cli`, and scope providers for:
  - hash determinism,
  - context facts behavior,
  - compatibility fallback,
  - registry scope-pack normalization and sync,
  - ruleset/CI scope-pack gate behavior.

## Deferred (Intentionally Out of Scope)
- DSL `import scope_pack`.
- Derived predicates.
- `bool3` semantics.

## Verification Snapshot
Executed on 2026-02-14:
- `cargo test -p admit_core -p admit_cli -p admit_scope_git -p admit_scope_deps -p admit_scope_github -p admit_scope_rust -p admit_scope_text -p admit_scope_ingest`
- Result: pass (all tests green in selected crates and their integration/doc tests).
