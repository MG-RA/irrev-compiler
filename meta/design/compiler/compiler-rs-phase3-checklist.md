# Phase 3 Checklist (Deterministic semantics + witness discipline)

Status date: 2026-01-29
Applies to: `meta/design/compiler/compiler-rs-plan.md` Phase 3

## 0) Baseline checkpoint

- [ ] `TEST_BASELINE.md` recording current test pass/fail state.

## 1) Evaluator surface (`admit_core::eval`)

- [ ] Implement pure `eval(program, query, EvalOpts)` entrypoint with deterministic options (displacement mode, ordering, float policy).

## 2) Environment builder (`admit_core::env`)

- [ ] Build `Env` with deterministic decls/permissions/erasure rules/commits/constraints.
- [ ] Emit `BuildError`s ordered by span/message.
- [ ] Decide where `permission_used`/`erasure_rule_used` facts are emitted.

## 3) Boolean logic + predicates

- [ ] Add `admit_core::bool_expr` + `admit_core::predicates`.
- [ ] Implement `eval_bool` with deterministic short-circuit and fact logging.
- [ ] Implement `EraseAllowed`, `DisplacedTotal`, `HasCommit`, `CommitEquals`, `CommitCmp` with unit checks.

## 4) Displacement trace (`admit_core::displacement`)

- [ ] Sum bucket totals for allowed diffs.
- [ ] Build ordered contributions list.
- [ ] Enforce "allow + no rule → inadmissible".

## 5) Constraint application (`admit_core::constraints`)

- [ ] Evaluate each constraint expression.
- [ ] Collect all `constraint_triggered` facts before verdict decision.

## 6) Witness assembly (`admit_core::witness`)

- [ ] Assemble sorted facts, reason, and displacement trace.
- [ ] Provide canonical predicate formatting.

## 7) Tests + fixtures

- [ ] Fixtures: allow triggers, deny blocks, allow without rule, unit mismatch, commit predicates.
- [ ] Golden JSON + canonical CBOR hash assertions (Phase 3).

## 8) CBOR discipline (`admit_core::cbor`)

- [ ] Provide helper enforcing canonical RFC 8949 encoding (no floats, normalized keys).
- [ ] Use helper in tests to compute stable witness hashes.
