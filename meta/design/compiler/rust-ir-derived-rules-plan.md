## Irreversibility-First Plan Design Prompt (Compiler Integration)

### 1. Action Definition

Prompt ID: `action_definition`

Answer:

Add a compiler-native derived rules scope for Rust irreversibility checks and wire it into the existing `admit_cli` execution surfaces so rule evaluation, witness emission, and projection are first-class compiler operations. The initial scope implements IR-RS-02, IR-RS-03, IR-RS-04, IR-RS-05, and IR-RS-08 as enforced checks, with IR-RS-01, 06, 07, 09, 10, 11, and 12 staged behind the same scope version track.

---

### 2. Boundary Declaration

Prompt ID: `boundary_declaration`

Answer:

Allowed changes: `crates/admit_cli`, `crates/admit_core`, optional new compiler crate for Rust lint walkers, schema/registry entries, and test fixtures under `testdata/` and crate test directories. In scope artifacts: `out/artifacts/` plan and lint witnesses, ledger events, optional DAG trace projection rows. Must not change: DSL language semantics unrelated to linting, existing plan-witness schema contracts, and unrelated vault ingestion behavior. Out of bounds for this plan: broad refactors of projection runtime and non-Rust language rule engines.

---

### 3. Persistence Analysis

Prompt ID: `persistence_analysis`

Answer:

Persistent differences include new rule identifiers, scope registration (`scope:rust.ir_lint@0`), witness schema (`rust.ir_lint_witness@1`), CI gating behavior, and deterministic fixture outputs. Once merged, downstream runs and governance queries will depend on these identifiers and emitted fields (`projection_run_id`, `trace_sha256`, batch identity). Undoing requires removing schema entries, migrating tests, and cleaning historical witness interpretation paths.

---

### 4. Erasure Cost

Prompt ID: `erasure_cost`

Answer:

Erasure grade: Grade 2 (costly/lossy to reverse). Reversal would require deleting or deprecating newly introduced witness/schema IDs, removing CI policy checks, and rewriting golden fixtures and governance queries. Historical plan/lint evidence created under the new ruleset cannot be unmade; only superseded by newer schema versions.

---

### 5. Displacement & Ownership

Prompt ID: `displacement_ownership`

Answer:

Primary cost is borne by compiler maintainers and CI owners: maintaining deterministic lints, fixtures, and projection contracts. Secondary cost is borne by contributors whose changes may newly fail on rule violations. Displacement is explicit: the compiler repository owns enforcement logic and witness compatibility, while users receive clear violation diagnostics and migration guidance.

---

### 6. Preconditions

Prompt ID: `preconditions`

Answer:

Required before execution: (1) canonical rule spec text for IR-RS-01..12 checked into repo docs, (2) deterministic test harness for witness/golden outputs, (3) registry path for new scope/schema IDs, (4) agreed allowlist strategy for temporary exceptions, (5) baseline scan of current violations to avoid blind fail-on-merge rollout. Evidence: committed spec document, passing baseline test snapshot, and recorded baseline violation report artifact.

---

### 7. Execution Constraints

Prompt ID: `execution_constraints`

Answer:

Implement in phases with explicit gates: Phase A fast lints (regex/import checks), Phase B AST-backed checks, Phase C full witness+projection integration. Hard constraints: deterministic ordering, no nondeterministic time/RNG in court outputs, no silent delete enforcement bypass, stable batch hash independent of batch size, and typed errors across boundaries. Abort conditions: nondeterministic fixture diffs, missing required witness fields, or schema IDs introduced without registry binding.

---

### 8. Postconditions

Prompt ID: `postconditions`

Answer:

Success evidence: (1) `admit_cli` command path for rust ir rules executes and emits a canonical witness artifact, (2) registry includes scope and schema IDs, (3) tests prove enforcement of IR-RS-02/03/04/05/08 with deterministic fixtures, (4) ledger/projection records rule results with run attribution, and (5) documentation describes remediation for each rule ID. Artifacts required: witness JSON+CBOR, ledger event, golden fixture outputs, and CI job logs.

---

### 9. Accountability

Prompt ID: `accountability`

Answer:

Acting entity: compiler maintainers operating via `admit_cli` in repository-controlled CI and local developer workflows. Authority: repository governance for compiler/runtime correctness and irreversibility accounting guarantees. Responsibility identifiers: git commit SHA, plan witness hash, and CI run identifier attached to rule-witness emission.

---

### 10. Acceptance Criteria

Prompt ID: `acceptance_criteria`

Answer:

Done means: IR-RS-02/03/04/05/08 are enforced in compiler checks with deterministic tests; scope+schema IDs are versioned and queryable; violation output is stable and attributable; and docs include rollout policy for the remaining rules. Unacceptable outcomes: style-only checks masquerading as invariants, nondeterministic witness output, bypassable destructive operations without witness notes, or fail-closed rollout without baseline/migration support.

---

### 11. Refusal Conditions

Prompt ID: `refusal_conditions`

Answer:

Do not execute if any are true: no agreed canonical rule definitions; no deterministic fixture baseline; inability to stamp provenance fields on projected writes; inability to map violations to stable rule IDs; or required schema/registry additions are blocked. Hard stop if enforcement would produce false confidence by omitting witness attribution.

---

### 12. Final Check

Prompt ID: `final_check`

Answer:

Yes, if implemented exactly as bounded above: irreversible effects are scoped to versioned rule/schema additions; erasure cost is declared as Grade 2 and accepted by maintainers; ownership is explicit via maintainer/CI governance; and future readers can reconstruct intent through plan witness, rule IDs, registry entries, and deterministic artifacts.

---
