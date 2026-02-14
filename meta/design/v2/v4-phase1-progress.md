# v4 Phase 1 Progress (Provider Contracts + Scope-Pack Linking)

Status date: 2026-02-14

## Scope
This tracks implementation progress for the v4 Phase 1 plan:
- typed provider predicate contracts
- implicit predicate eval context (facts/snapshot metadata)
- provider-pack hash linking via meta-registry scope packs
- warn/error gate behavior in ruleset check and CI

## Status Summary
- Overall Phase 1 status: Complete
- Compatibility window (`params.facts` fallback): Active (intentionally kept)
- DSL `import scope_pack`, derived predicates, `bool3`: Out of scope for this phase

## Checklist
1. Core contracts and hashing
- [x] `PredicateDescriptor` includes `predicate_id`, `result_kind`, `emits_findings`, optional `evidence_schema`.
- [x] `PredicateEvalContext` added with `facts`, `snapshot_hash`, `facts_schema_id`.
- [x] `provider_pack_hash()` implemented with canonical CBOR normalization.
- [x] Hash identity excludes `doc` text; deterministic tests added.

2. Rules engine context wiring
- [x] Rules engine builds `PredicateEvalContext` from input bundles.
- [x] Legacy injection (`facts`, `snapshot_hash`, `facts_schema_id`) still merged into effective params for compatibility.
- [x] Provider evaluation now receives both params and context.

3. Provider migration
- [x] Workspace providers migrated to new `eval_predicate(..., ctx)` signature.
- [x] `git`, `deps`, `github`, `rust`, `text` predicates read context facts first, then fallback to `params.facts`.
- [x] `facts` removed from required policy params in provider predicate schemas.
- [x] `ingest` updated for descriptor fields + signature only.

4. Registry model and normalization
- [x] `MetaRegistryV1` includes additive `scope_packs`.
- [x] Scope pack normalization includes sort/dedupe and hash/predicate validation.
- [x] Schema remains additive `meta-registry/1`.

5. Runtime linking + gate behavior
- [x] Runtime computes provider descriptor hashes and compares against registry `scope_packs` by `(scope_id, version)`.
- [x] `warn` mode records warning facts and continues.
- [x] `error` mode fails deterministically.
- [x] Warning fact IDs implemented: `provider/scope_pack_missing`, `provider/scope_pack_mismatch`.

6. Registry sync command
- [x] `admit registry scope-pack-sync --input --out` implemented.
- [x] Built-in provider packs upserted deterministically; `registry_version` increments on write.

7. Documentation
- [x] `docs/spec/provider-protocol.md` updated for typed predicate contract, eval context, pack hash identity.
- [x] Migration note for legacy `params.facts` compatibility included.
- [x] Example invocations no longer require explicit `facts` transport params.

## Validation Run (2026-02-14)
- `cargo test -p admit_core`
- `cargo test -p admit_scope_git -p admit_scope_deps -p admit_scope_github -p admit_scope_rust -p admit_scope_text -p admit_scope_ingest`
- `cargo test -p admit_cli --test registry`
- `cargo test -p admit_cli --test ruleset_check`
- `cargo test -p admit_cli --test ci_command`

All commands above passed in this workspace.

## Remaining Items
1. Phase 2 cleanup (planned): remove legacy `params.facts` fallback once downstream rulesets/providers fully migrate.
2. Optional process hardening: add local pre-commit/PR helper that runs `admit plan autogen` before enforce checks.
3. Documentation cleanup: `meta/design/v2/v4.md` currently does not reflect this structured status and can be normalized to this tracker format.
